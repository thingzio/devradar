// Package converter normalizes raw scanner JSON into the scanner-agnostic
// data.Vulnerability type. Each scanner has a Converter; a registry detects the
// right one by inspecting the document. (Design from vimp, reimplemented
// natively — no dependency on that project.)
package converter

import (
	"context"
	"errors"

	"github.com/Jeffail/gabs/v2"
	"github.com/thingzio/devradar/pkg/data"
)

// ErrNoConverter is returned when no registered converter recognizes a document.
var ErrNoConverter = errors.New("converter: no converter for document")

// Converter turns one scanner's JSON output into normalized findings.
type Converter interface {
	// Name is the converter identifier, e.g. "grype", "trivy".
	Name() string
	// CanHandle reports whether this converter recognizes the document.
	CanHandle(c *gabs.Container) bool
	// Convert normalizes the document into findings.
	Convert(ctx context.Context, c *gabs.Container) ([]data.Vulnerability, error)
}

// Registry holds converters and detects the right one per document.
type Registry struct {
	converters []Converter
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a converter.
func (r *Registry) Register(c Converter) { r.converters = append(r.converters, c) }

// Detect returns the first converter that recognizes the document, or
// ErrNoConverter.
func (r *Registry) Detect(c *gabs.Container) (Converter, error) {
	if c == nil {
		return nil, ErrNoConverter
	}
	for _, conv := range r.converters {
		if conv.CanHandle(c) {
			return conv, nil
		}
	}
	return nil, ErrNoConverter
}

// Get returns a converter by name.
func (r *Registry) Get(name string) (Converter, bool) {
	for _, conv := range r.converters {
		if conv.Name() == name {
			return conv, true
		}
	}
	return nil, false
}
