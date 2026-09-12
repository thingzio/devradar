// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
