package delivery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
	drnet "github.com/thingzio/devradar/pkg/net"
)

func TestRunnerBoundsConcurrencyAtFive(t *testing.T) {
	store := newFakeStore(t, 12)
	entered := make(chan struct{}, 12)
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	sender := senderFunc(func(ctx context.Context, _ drnet.Message) (drnet.Receipt, error) {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return drnet.Receipt{}, ctx.Err()
		}
		active.Add(-1)
		return drnet.Receipt{ID: fmt.Sprintf("receipt-%d", current)}, nil
	})
	runner := testRunner(store, sender)

	done := make(chan error, 1)
	go func() { done <- runner.run(context.Background()) }()
	for range 5 {
		<-entered
	}
	select {
	case <-entered:
		t.Fatal("sixth send started before a concurrency slot was released")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := maximum.Load(); got != 5 {
		t.Fatalf("maximum concurrency = %d, want 5", got)
	}
	if got := store.completedCount(); got != 12 {
		t.Fatalf("completed = %d, want 12", got)
	}
}

func TestRunnerSkipsBatchWhenNoDurableWorkerSlotIsAvailable(t *testing.T) {
	store := newFakeStore(t, 1)
	store.availableSlots = 0
	runner := testRunner(store, senderFunc(func(context.Context, drnet.Message) (drnet.Receipt, error) {
		t.Fatal("sender called without a durable worker slot")
		return drnet.Receipt{}, nil
	}))
	if err := runner.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.leaseCalls != 0 {
		t.Fatalf("lease calls = %d, want 0", store.leaseCalls)
	}
}

func TestRunnerCancellationWaitsForStartedWorkers(t *testing.T) {
	store := newFakeStore(t, 50)
	started := make(chan struct{}, 5)
	var exited atomic.Int32
	sender := senderFunc(func(ctx context.Context, _ drnet.Message) (drnet.Receipt, error) {
		started <- struct{}{}
		<-ctx.Done()
		exited.Add(1)
		return drnet.Receipt{}, ctx.Err()
	})
	runner := testRunner(store, sender)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.run(ctx) }()
	for range 5 {
		<-started
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run error = %v, want context canceled", err)
	}
	if got := exited.Load(); got != 5 {
		t.Fatalf("exited workers = %d, want 5", got)
	}
}

func TestRunnerAppliesTenSecondChildDeadline(t *testing.T) {
	store := newFakeStore(t, 1)
	sender := senderFunc(func(ctx context.Context, _ drnet.Message) (drnet.Receipt, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("sender context has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining <= 9*time.Second || remaining > 10*time.Second {
			t.Fatalf("sender deadline remaining = %s, want (9s,10s]", remaining)
		}
		return drnet.Receipt{ID: "receipt-deadline"}, nil
	})
	if err := testRunner(store, sender).run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestRunnerRetriesTransientProviderErrorsWithBoundedExponentialJitter(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		attempt int
		random  float64
		want    time.Duration
	}{
		{name: "first lower", attempt: 1, random: 0, want: 30 * time.Second},
		{name: "first upper", attempt: 1, random: 1, want: 90 * time.Second},
		{name: "fourth lower", attempt: 4, random: 0, want: 4 * time.Minute},
		{name: "fourth upper", attempt: 4, random: 1, want: 12 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeStore(t, 1)
			store.deliveries[0].AttemptCount = test.attempt
			store.deliveries[0].FirstAttemptAt = now
			store.deliveries[0].InvitationExpiresAt = now.Add(24 * time.Hour)
			runner := testRunner(store, senderFunc(func(context.Context, drnet.Message) (drnet.Receipt, error) {
				return drnet.Receipt{}, &drnet.ProviderError{StatusCode: http.StatusServiceUnavailable, Name: "internal_server_error", Message: "provider request failed"}
			}))
			runner.now = func() time.Time { return now }
			runner.randomFloat = func() float64 { return test.random }
			if err := runner.run(context.Background()); err != nil {
				t.Fatalf("run: %v", err)
			}
			if got := store.singleTransition(t); got.kind != transitionRetry || got.delay != test.want {
				t.Fatalf("transition = %+v, want retry delay %s", got, test.want)
			}
		})
	}
}

func TestRunnerTerminalizesAtAttemptHorizonAndInvitationExpiry(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		attempt   int
		first     time.Time
		expiresAt time.Time
	}{
		{name: "eighth attempt", attempt: 8, first: now.Add(-time.Hour), expiresAt: now.Add(time.Hour)},
		{name: "retry crosses 23 hour horizon", attempt: 7, first: now.Add(-22*time.Hour - 30*time.Minute), expiresAt: now.Add(2 * time.Hour)},
		{name: "retry crosses invitation expiry", attempt: 2, first: now.Add(-time.Minute), expiresAt: now.Add(10 * time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeStore(t, 1)
			store.deliveries[0].AttemptCount = test.attempt
			store.deliveries[0].FirstAttemptAt = test.first
			store.deliveries[0].InvitationExpiresAt = test.expiresAt
			runner := testRunner(store, senderFunc(func(context.Context, drnet.Message) (drnet.Receipt, error) {
				return drnet.Receipt{}, &drnet.ProviderError{StatusCode: http.StatusTooManyRequests, Name: "rate_limit_exceeded", Message: "provider request failed"}
			}))
			runner.now = func() time.Time { return now }
			runner.randomFloat = func() float64 { return 0 }
			if err := runner.run(context.Background()); err != nil {
				t.Fatalf("run: %v", err)
			}
			if got := store.singleTransition(t); got.kind != transitionPermanent {
				t.Fatalf("transition = %+v, want permanent failure", got)
			}
		})
	}
}

func TestRunnerCancelsStaleInvitationBeforeDecryptOrSend(t *testing.T) {
	store := newFakeStore(t, 1)
	store.current = false
	var sends atomic.Int32
	runner := testRunner(store, senderFunc(func(context.Context, drnet.Message) (drnet.Receipt, error) {
		sends.Add(1)
		return drnet.Receipt{ID: "unexpected"}, nil
	}))
	runner.open = func([]byte, string, []byte) ([]byte, error) {
		t.Fatal("stale delivery was decrypted")
		return nil, nil
	}
	if err := runner.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if sends.Load() != 0 {
		t.Fatal("stale delivery was sent")
	}
	if got := store.singleTransition(t); got.kind != transitionCancel || !got.scrubbed {
		t.Fatalf("transition = %+v, want ciphertext-scrubbing cancellation", got)
	}
}

func TestRunnerZeroesPlaintextAndRendersFixedInvitationTemplate(t *testing.T) {
	store := newFakeStore(t, 1)
	plaintext := []byte("raw-invitation-token")
	runner := testRunner(store, senderFunc(func(_ context.Context, message drnet.Message) (drnet.Receipt, error) {
		for i, b := range plaintext {
			if b != 0 {
				t.Fatalf("plaintext byte %d remained live when sender started", i)
			}
		}
		if message.Subject != "You have been invited to DevRadar" {
			t.Fatalf("subject = %q", message.Subject)
		}
		wantLink := "https://devradar.example/invitations/raw-invitation-token"
		if !strings.Contains(message.HTML, wantLink) || !strings.Contains(message.Text, wantLink) {
			t.Fatalf("message does not contain fixed invitation link: %+v", message)
		}
		return drnet.Receipt{ID: "receipt-template"}, nil
	}))
	runner.open = func(_ []byte, stored string, aad []byte) ([]byte, error) {
		if stored != store.deliveries[0].EncryptedPayload || string(aad) != store.deliveries[0].IdempotencyKey {
			t.Fatalf("open binding stored=%q aad=%q", stored, aad)
		}
		return plaintext, nil
	}
	if err := runner.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	for i, b := range plaintext {
		if b != 0 {
			t.Fatalf("plaintext byte %d = %d, want zero", i, b)
		}
	}
	if got := store.singleTransition(t); got.kind != transitionComplete || !got.scrubbed {
		t.Fatalf("transition = %+v, want ciphertext-scrubbing completion", got)
	}
}

func TestRunnerPersistsProviderFailureAndContinuesBatch(t *testing.T) {
	store := newFakeStore(t, 3)
	sender := senderFunc(func(_ context.Context, message drnet.Message) (drnet.Receipt, error) {
		if message.To == "invitee-1@example.com" {
			return drnet.Receipt{}, &drnet.ProviderError{StatusCode: http.StatusBadRequest, Name: "invalid_recipient", Message: "provider request failed"}
		}
		return drnet.Receipt{ID: "receipt-" + message.To}, nil
	})
	if err := testRunner(store, sender).run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if store.completedCount() != 2 || store.permanentCount() != 1 {
		t.Fatalf("transitions = %+v, want two complete and one permanent", store.transitionsCopy())
	}
}

func TestRunnerPersistsBoundedProviderStatusWithoutReflectedText(t *testing.T) {
	const reflectedSecret = "raw-invitation-token"
	for _, test := range []struct {
		name   string
		status int
		kind   string
	}{
		{name: "transient", status: http.StatusServiceUnavailable, kind: transitionRetry},
		{name: "permanent", status: http.StatusBadRequest, kind: transitionPermanent},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeStore(t, 1)
			runner := testRunner(store, senderFunc(func(context.Context, drnet.Message) (drnet.Receipt, error) {
				return drnet.Receipt{}, &drnet.ProviderError{StatusCode: test.status, Name: reflectedSecret, Message: reflectedSecret}
			}))
			if err := runner.run(context.Background()); err != nil {
				t.Fatalf("run: %v", err)
			}
			got := store.singleTransition(t)
			if got.kind != test.kind || !strings.Contains(got.message, fmt.Sprint(test.status)) {
				t.Fatalf("transition = %+v, want %s with status %d", got, test.kind, test.status)
			}
			if strings.Contains(got.message, reflectedSecret) {
				t.Fatalf("persisted provider error reflected secret: %q", got.message)
			}
		})
	}
}

func TestRunnerReturnsAccountFilteredInfrastructureErrors(t *testing.T) {
	store := newFakeStore(t, 1)
	store.currentErr = errors.New("database unavailable")
	if err := testRunner(store, senderFunc(func(context.Context, drnet.Message) (drnet.Receipt, error) {
		return drnet.Receipt{}, errors.New("must not send")
	})).run(context.Background()); err == nil || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatalf("run error = %v, want database unavailable", err)
	}
	if store.lastCurrentAccount != store.deliveries[0].AccountID {
		t.Fatalf("revalidation account = %q, want %q", store.lastCurrentAccount, store.deliveries[0].AccountID)
	}
}

type senderFunc func(context.Context, drnet.Message) (drnet.Receipt, error)

func (f senderFunc) Send(ctx context.Context, message drnet.Message) (drnet.Receipt, error) {
	return f(ctx, message)
}

const (
	transitionComplete  = "complete"
	transitionRetry     = "retry"
	transitionPermanent = "permanent"
	transitionCancel    = "cancel"
)

type transition struct {
	kind      string
	accountID string
	id        string
	owner     string
	attempt   int
	delay     time.Duration
	message   string
	scrubbed  bool
}

type fakeStore struct {
	mu                 sync.Mutex
	deliveries         []postgres.Delivery
	current            bool
	currentErr         error
	availableSlots     int
	leaseCalls         int
	lastCurrentAccount string
	transitions        []transition
}

func newFakeStore(t *testing.T, count int) *fakeStore {
	t.Helper()
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	deliveries := make([]postgres.Delivery, count)
	for i := range deliveries {
		deliveries[i] = postgres.Delivery{
			ID:                  fmt.Sprintf("delivery-%d", i),
			AccountID:           fmt.Sprintf("account-%d", i),
			Kind:                "account_invitation",
			InvitationID:        fmt.Sprintf("invitation-%d", i),
			InvitationVersion:   1,
			InvitationExpiresAt: now.Add(24 * time.Hour),
			Recipient:           fmt.Sprintf("invitee-%d@example.com", i),
			EncryptedPayload:    "enc:ciphertext",
			IdempotencyKey:      fmt.Sprintf("account-invitation/invitation-%d/1", i),
			AttemptCount:        1,
			FirstAttemptAt:      now,
			LeaseOwner:          "owner",
			LeaseExpiresAt:      now.Add(5 * time.Minute),
		}
	}
	return &fakeStore{deliveries: deliveries, current: true, availableSlots: 5}
}

func (s *fakeStore) LeaseDeliveries(_ context.Context, owner string, limit int, _ time.Duration) ([]postgres.Delivery, error) {
	s.mu.Lock()
	s.leaseCalls++
	s.mu.Unlock()
	if limit > 50 {
		return nil, fmt.Errorf("limit = %d, want <= 50", limit)
	}
	rows := append([]postgres.Delivery(nil), s.deliveries...)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	for i := range rows {
		rows[i].LeaseOwner = owner
	}
	return rows, nil
}

func (s *fakeStore) LeaseDeliverySlots(_ context.Context, owner string, limit int, _ time.Duration) ([]postgres.DeliverySlot, error) {
	count := min(s.availableSlots, limit)
	slots := make([]postgres.DeliverySlot, count)
	for i := range slots {
		slots[i] = postgres.DeliverySlot{Slot: i + 1, LeaseOwner: owner, Generation: 1}
	}
	return slots, nil
}

func (s *fakeStore) ReleaseDeliverySlots(_ context.Context, _ string, _ []postgres.DeliverySlot) error {
	return nil
}

func (s *fakeStore) DeliveryInvitationCurrent(_ context.Context, accountID, _ string, _ int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCurrentAccount = accountID
	return s.current, s.currentErr
}

func (s *fakeStore) CompleteDelivery(_ context.Context, accountID, id, owner string, attempt int, _ string) error {
	s.record(transition{kind: transitionComplete, accountID: accountID, id: id, owner: owner, attempt: attempt, scrubbed: true})
	return nil
}

func (s *fakeStore) RetryDelivery(_ context.Context, accountID, id, owner string, attempt int, message string, delay time.Duration) error {
	s.record(transition{kind: transitionRetry, accountID: accountID, id: id, owner: owner, attempt: attempt, delay: delay, message: message})
	return nil
}

func (s *fakeStore) PermanentlyFailDelivery(_ context.Context, accountID, id, owner string, attempt int, message string) error {
	s.record(transition{kind: transitionPermanent, accountID: accountID, id: id, owner: owner, attempt: attempt, message: message, scrubbed: true})
	return nil
}

func (s *fakeStore) CancelDelivery(_ context.Context, accountID, id, owner string, attempt int, _ string) error {
	s.record(transition{kind: transitionCancel, accountID: accountID, id: id, owner: owner, attempt: attempt, scrubbed: true})
	return nil
}

func (s *fakeStore) record(got transition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transitions = append(s.transitions, got)
}

func (s *fakeStore) transitionsCopy() []transition {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]transition(nil), s.transitions...)
}

func (s *fakeStore) completedCount() int { return s.count(transitionComplete) }
func (s *fakeStore) permanentCount() int { return s.count(transitionPermanent) }

func (s *fakeStore) count(kind string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, got := range s.transitions {
		if got.kind == kind {
			count++
		}
	}
	return count
}

func (s *fakeStore) singleTransition(t *testing.T) transition {
	t.Helper()
	got := s.transitionsCopy()
	if len(got) != 1 {
		t.Fatalf("transition count = %d, want 1: %+v", len(got), got)
	}
	return got[0]
}

func testRunner(store *fakeStore, sender drnet.Sender) *runner {
	return &runner{
		store:           store,
		sender:          sender,
		key:             make([]byte, 32),
		baseURL:         "https://devradar.example",
		owner:           "owner",
		batchSize:       50,
		concurrency:     5,
		requestDeadline: 10 * time.Second,
		maxAttempts:     8,
		retryHorizon:    23 * time.Hour,
		now:             func() time.Time { return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC) },
		randomFloat:     func() float64 { return 0.5 },
		open: func(_ []byte, _ string, _ []byte) ([]byte, error) {
			return []byte("raw-invitation-token"), nil
		},
	}
}
