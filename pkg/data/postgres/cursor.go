package postgres

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// defaultPageLimit / maxPageLimit bound every paginated list endpoint. A caller
// may ask for fewer; anything outside (0, maxPageLimit] snaps to the default.
const (
	defaultPageLimit = 100
	maxPageLimit     = 1000
)

// keysetCursor is an opaque continuation token for keyset (seek) pagination. It
// carries the ordering key of the last row returned — a timestamp plus a unique
// tiebreaker id — so the next page seeks past it with a (ts, id) row comparison
// rather than OFFSET (which degrades and can skip/duplicate rows under writes).
type keysetCursor struct {
	TS  time.Time `json:"t,omitzero"`
	N   int64     `json:"n,omitempty"`
	Str string    `json:"s,omitempty"` // secondary string key (e.g. exposure)
	ID  string    `json:"i"`
}

// encodeCursor returns an opaque base64 token for a time-keyed list, or "" when
// there is no next page.
func encodeCursor(ts time.Time, id string) string {
	b, err := json.Marshal(keysetCursor{TS: ts.UTC(), ID: id})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// encodeCursorN returns an opaque base64 token for an integer-keyed list (e.g. a
// risk score), with id as the unique tiebreaker.
func encodeCursorN(n int64, id string) string {
	b, err := json.Marshal(keysetCursor{N: n, ID: id})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// encodeCursorNS returns a token for a list ordered by (int, string, id) — e.g.
// findings ordered by (severity_rank, exposure, finding_id).
func encodeCursorNS(n int64, str, id string) string {
	b, err := json.Marshal(keysetCursor{N: n, Str: str, ID: id})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor parses a token from encodeCursor. ok is false for an empty string
// (first page) or a malformed token (treated as first page, never an error).
func decodeCursor(s string) (c keysetCursor, ok bool) {
	if s == "" {
		return keysetCursor{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return keysetCursor{}, false
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return keysetCursor{}, false
	}
	return c, true
}

// clampLimit normalizes a requested page size and asks for one extra row so the
// caller can tell whether a further page exists without a second COUNT query.
func clampLimit(limit int) (effective, fetch int) {
	if limit <= 0 || limit > maxPageLimit {
		limit = defaultPageLimit
	}
	return limit, limit + 1
}
