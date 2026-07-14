// Package delivery processes the bounded transactional email outbox.
package delivery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data/postgres"
	drnet "github.com/thingzio/devradar/pkg/net"
	"github.com/thingzio/devradar/pkg/secretbox"
)

const (
	deliveryLeaseDuration     = 5 * time.Minute
	deliverySlotLeaseDuration = 6 * time.Minute
	maxDeliveriesPerSlot      = 10
	retryBaseDelay            = time.Minute
	invitationSubject         = "You have been invited to DevRadar"
)

// Options carries build metadata for one delivery command execution.
type Options struct {
	Version string
	Commit  string
	Date    string
}

// Store is the delivery worker's durable global capacity and account-filtered
// outbox subset.
type Store interface {
	LeaseDeliverySlots(context.Context, string, int, time.Duration) ([]postgres.DeliverySlot, error)
	ReleaseDeliverySlots(context.Context, string, []postgres.DeliverySlot) error
	LeaseDeliveries(context.Context, string, int, time.Duration) ([]postgres.Delivery, error)
	DeliveryInvitationCurrent(context.Context, string, string, int) (bool, error)
	CompleteDelivery(context.Context, string, string, string, int, string) error
	RetryDelivery(context.Context, string, string, string, int, string, time.Duration) error
	PermanentlyFailDelivery(context.Context, string, string, string, int, string) error
	CancelDelivery(context.Context, string, string, string, int, string) error
}

type runner struct {
	store           Store
	sender          drnet.Sender
	key             []byte
	baseURL         string
	owner           string
	batchSize       int
	concurrency     int
	requestDeadline time.Duration
	maxAttempts     int
	retryHorizon    time.Duration
	now             func() time.Time
	randomFloat     func() float64
	open            func([]byte, string, []byte) ([]byte, error)
}

// Run validates environment configuration, wires production dependencies, and
// executes one bounded delivery pass.
func Run(ctx context.Context, opts Options) error {
	if err := config.ValidateDelivery(); err != nil {
		return err
	}
	key, err := config.DeliveryKey()
	if err != nil {
		return fmt.Errorf("delivery key: %w", err)
	}
	store, err := postgres.New(ctx, config.DatabaseURL(), deliveryPoolConfig())
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer func() { _ = store.Close() }()

	var sender drnet.Sender
	if apiKey := config.SendAPIKey(); apiKey != "" {
		sender = drnet.ResendSender{APIKey: apiKey, From: config.EmailFrom()}
	} else if config.DevMode() {
		sender = drnet.LogSender{}
	} else {
		return fmt.Errorf("SEND_API_KEY is required outside development mode")
	}
	owner, err := newLeaseOwner()
	if err != nil {
		return err
	}

	slog.Info("delivery pass starting", "version", opts.Version, "commit", opts.Commit, "date", opts.Date)
	r := &runner{
		store:           store,
		sender:          sender,
		key:             key,
		baseURL:         strings.TrimRight(config.BaseURL(), "/"),
		owner:           owner,
		batchSize:       config.DeliveryBatchSize(),
		concurrency:     config.DeliveryConcurrency(),
		requestDeadline: config.DeliveryRequestDeadline(),
		maxAttempts:     config.DeliveryMaxAttempts(),
		retryHorizon:    config.DeliveryRetryHorizon(),
		now:             time.Now,
		randomFloat:     secureRandomFloat,
		open:            secretbox.Open,
	}
	return r.run(ctx)
}

func (r *runner) run(ctx context.Context) (err error) {
	slots, err := r.store.LeaseDeliverySlots(ctx, r.owner, r.concurrency, deliverySlotLeaseDuration)
	if err != nil {
		return fmt.Errorf("lease delivery worker slots: %w", err)
	}
	if len(slots) == 0 {
		slog.Info("delivery pass skipped; no global worker slot is available")
		return nil
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if releaseErr := r.store.ReleaseDeliverySlots(releaseCtx, r.owner, slots); releaseErr != nil {
			err = errors.Join(err, fmt.Errorf("release delivery worker slots: %w", releaseErr))
		}
	}()

	limit := min(r.batchSize, len(slots)*maxDeliveriesPerSlot)
	return r.runWithCapacity(ctx, limit, len(slots))
}

func (r *runner) runWithCapacity(ctx context.Context, limit, concurrency int) error {
	deliveries, err := r.store.LeaseDeliveries(ctx, r.owner, limit, deliveryLeaseDuration)
	if err != nil {
		return fmt.Errorf("lease deliveries: %w", err)
	}
	if len(deliveries) == 0 {
		slog.Info("delivery pass complete", "leased", 0)
		return nil
	}

	group, groupCtx := errgroup.WithContext(ctx)
	semaphore := make(chan struct{}, concurrency)
	scheduled := 0
schedule:
	for i := range deliveries {
		select {
		case semaphore <- struct{}{}:
		case <-groupCtx.Done():
			break schedule
		}
		delivery := deliveries[i]
		scheduled++
		group.Go(func() error {
			defer func() { <-semaphore }()
			return r.deliver(groupCtx, delivery)
		})
	}
	if err := group.Wait(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	slog.Info("delivery pass complete", "leased", len(deliveries), "processed", scheduled)
	return nil
}

func (r *runner) deliver(ctx context.Context, delivery postgres.Delivery) error {
	current, err := r.store.DeliveryInvitationCurrent(ctx, delivery.AccountID, delivery.InvitationID, delivery.InvitationVersion)
	if err != nil {
		return fmt.Errorf("revalidate delivery %s for account %s: %w", delivery.ID, delivery.AccountID, err)
	}
	if !current || !r.now().Before(delivery.InvitationExpiresAt) {
		return r.cancel(ctx, delivery, "invitation is no longer current")
	}
	if delivery.Kind != "account_invitation" {
		return r.permanentlyFail(ctx, delivery, "unsupported delivery kind")
	}
	if delivery.AttemptCount > r.maxAttempts || retryHorizonElapsed(r.now(), delivery.FirstAttemptAt, r.retryHorizon) {
		return r.permanentlyFail(ctx, delivery, "delivery retry limit exceeded")
	}

	plaintext, err := r.open(r.key, delivery.EncryptedPayload, []byte(delivery.IdempotencyKey))
	delivery.EncryptedPayload = ""
	if err != nil {
		return r.permanentlyFail(ctx, delivery, "delivery payload could not be decrypted")
	}
	defer zeroBytes(plaintext)
	if len(plaintext) == 0 {
		return r.permanentlyFail(ctx, delivery, "delivery payload was empty")
	}

	receipt, sendErr := r.sendInvitation(ctx, delivery, plaintext)
	if sendErr == nil {
		if err := r.store.CompleteDelivery(ctx, delivery.AccountID, delivery.ID, r.owner, delivery.AttemptCount, receipt.ID); err != nil {
			return fmt.Errorf("complete delivery %s for account %s: %w", delivery.ID, delivery.AccountID, err)
		}
		slog.Info("delivery completed", "account_id", delivery.AccountID, "delivery_id", delivery.ID, "attempt", delivery.AttemptCount)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if drnet.IsPermanentSenderError(sendErr) {
		return r.permanentlyFail(ctx, delivery, providerFailureMessage(sendErr))
	}

	delay := retryDelay(delivery.AttemptCount, r.randomFloat())
	nextAttempt := r.now().Add(delay)
	firstAttempt := delivery.FirstAttemptAt
	if firstAttempt.IsZero() {
		firstAttempt = r.now()
	}
	if delivery.AttemptCount >= r.maxAttempts ||
		!nextAttempt.Before(firstAttempt.Add(r.retryHorizon)) ||
		!nextAttempt.Before(delivery.InvitationExpiresAt) {
		return r.permanentlyFail(ctx, delivery, "delivery retry limit exceeded")
	}
	if err := r.store.RetryDelivery(ctx, delivery.AccountID, delivery.ID, r.owner, delivery.AttemptCount,
		providerFailureMessage(sendErr), delay); err != nil {
		return fmt.Errorf("retry delivery %s for account %s: %w", delivery.ID, delivery.AccountID, err)
	}
	slog.Warn("delivery scheduled for retry", "account_id", delivery.AccountID, "delivery_id", delivery.ID,
		"attempt", delivery.AttemptCount, "retry_delay", delay)
	return nil
}

func (r *runner) sendInvitation(ctx context.Context, delivery postgres.Delivery, plaintext []byte) (drnet.Receipt, error) {
	link := r.baseURL + "/invitations/" + url.PathEscape(string(plaintext))
	message := drnet.Message{
		To:             delivery.Recipient,
		Subject:        invitationSubject,
		HTML:           `<p>You have been invited to DevRadar.</p><p><a href="` + html.EscapeString(link) + `">Accept invitation</a></p>`,
		Text:           "You have been invited to DevRadar.\n\nAccept invitation: " + link,
		IdempotencyKey: delivery.IdempotencyKey,
	}
	zeroBytes(plaintext)
	requestCtx, cancel := context.WithTimeout(ctx, r.requestDeadline)
	defer cancel()
	return r.sender.Send(requestCtx, message)
}

func (r *runner) permanentlyFail(ctx context.Context, delivery postgres.Delivery, message string) error {
	if err := r.store.PermanentlyFailDelivery(ctx, delivery.AccountID, delivery.ID, r.owner, delivery.AttemptCount, message); err != nil {
		return fmt.Errorf("permanently fail delivery %s for account %s: %w", delivery.ID, delivery.AccountID, err)
	}
	slog.Warn("delivery permanently failed", "account_id", delivery.AccountID, "delivery_id", delivery.ID, "attempt", delivery.AttemptCount)
	return nil
}

func (r *runner) cancel(ctx context.Context, delivery postgres.Delivery, message string) error {
	if err := r.store.CancelDelivery(ctx, delivery.AccountID, delivery.ID, r.owner, delivery.AttemptCount, message); err != nil {
		return fmt.Errorf("cancel delivery %s for account %s: %w", delivery.ID, delivery.AccountID, err)
	}
	slog.Info("delivery canceled", "account_id", delivery.AccountID, "delivery_id", delivery.ID, "attempt", delivery.AttemptCount)
	return nil
}

func deliveryPoolConfig() postgres.PoolConfig {
	cfg := postgres.DefaultPoolConfig()
	cfg.AppName = "devradar-deliver"
	cfg.MaxOpenConns = config.GetEnvAsInt("DB_MAX_OPEN_CONNS", 7)
	cfg.MaxIdleConns = config.GetEnvAsInt("DB_MAX_IDLE_CONNS", 2)
	return cfg
}

func retryDelay(attempt int, randomFloat float64) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 16 {
		attempt = 16
	}
	base := retryBaseDelay * time.Duration(1<<(attempt-1))
	if randomFloat < 0 {
		randomFloat = 0
	}
	if randomFloat > 1 {
		randomFloat = 1
	}
	return base/2 + time.Duration(float64(base)*randomFloat)
}

func retryHorizonElapsed(now, first time.Time, horizon time.Duration) bool {
	return !first.IsZero() && !now.Before(first.Add(horizon))
}

func providerFailureMessage(err error) string {
	var providerErr *drnet.ProviderError
	if errors.As(err, &providerErr) {
		return fmt.Sprintf("email provider returned status %d", providerErr.StatusCode)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "email provider request timed out"
	}
	return "email provider request failed"
}

func newLeaseOwner() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate delivery lease owner: %w", err)
	}
	return "deliver/" + hex.EncodeToString(id[:]), nil
}

func secureRandomFloat() float64 {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0.5
	}
	return float64(binary.BigEndian.Uint64(value[:])>>11) / (1 << 53)
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
