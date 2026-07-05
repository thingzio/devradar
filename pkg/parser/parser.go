// Package parser holds small helpers for pulling typed values out of gabs
// containers without panicking on missing keys or unexpected types. Scanner
// output shapes vary across versions, so converters read defensively. (Same
// approach proven in vimp, reimplemented natively — no dependency on it.)
package parser

import (
	"fmt"

	"github.com/Jeffail/gabs/v2"
)

// ToString converts an arbitrary gabs value to a string, "" for nil.
func ToString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// FirstNonEmpty returns the first value that stringifies to non-empty.
func FirstNonEmpty(vals ...any) string {
	for _, v := range vals {
		if s := ToString(v); s != "" {
			return s
		}
	}
	return ""
}

// ToFloat32 converts a numeric gabs value to float32, 0 for nil/non-numeric.
func ToFloat32(v any) float32 {
	switch n := v.(type) {
	case float32:
		return n
	case float64:
		return float32(n)
	case int:
		return float32(n)
	case int32:
		return float32(n)
	case int64:
		return float32(n)
	case uint:
		return float32(n)
	case uint32:
		return float32(n)
	case uint64:
		return float32(n)
	default:
		return 0
	}
}

// String returns the first key on c that holds a non-empty string.
func String(c *gabs.Container, keys ...string) string {
	if c == nil || !c.Exists() {
		return ""
	}
	for _, k := range keys {
		if !c.Exists(k) {
			continue
		}
		if s := ToString(c.Search(k).Data()); s != "" {
			return s
		}
	}
	return ""
}
