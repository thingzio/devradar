package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

type requestIDContextKey struct{}

const requestIDHeader = "X-Request-ID"

var (
	readRequestIDEntropy     = rand.Read
	requestIDFallbackCounter atomic.Uint64
)

// RequestID assigns an untrusted request a server-generated correlation ID.
// Client-supplied X-Request-ID values are deliberately ignored as the primary
// identifier used by security logs and durable audit events.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := newRequestID()
		if err != nil {
			slog.Error("generate request id", "request_id", id, "error", err)
		}
		w.Header().Set(requestIDHeader, id)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newRequestID() (string, error) {
	var raw [16]byte
	n, err := readRequestIDEntropy(raw[:])
	if err == nil && n == len(raw) {
		return hex.EncodeToString(raw[:]), nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}

	var seed [16]byte
	binary.BigEndian.PutUint64(seed[:8], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint64(seed[8:], requestIDFallbackCounter.Add(1))
	sum := sha256.Sum256(seed[:])
	return hex.EncodeToString(sum[:16]), err
}

// RequestIDFromContext returns the server-generated request correlation ID.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDContextKey{}).(string)
	return id
}
