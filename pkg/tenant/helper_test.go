package tenant_test

import (
	"crypto/rand"
	"encoding/hex"
)

// randEmail returns a unique test email so parallel/repeated runs don't collide
// on the tenant email UNIQUE constraint.
func randEmail() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + "@example.com"
}
