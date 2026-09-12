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

package parser

import (
	"testing"

	"github.com/Jeffail/gabs/v2"
)

func TestToString(t *testing.T) {
	cases := map[any]string{
		"hi":     "hi",
		42:       "42",
		true:     "true",
		nil:      "",
		3.14:     "3.14",
		int64(7): "7",
	}
	for in, want := range cases {
		if got := ToString(in); got != want {
			t.Errorf("ToString(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := FirstNonEmpty(nil, "", "first", "second"); got != "first" {
		t.Errorf("FirstNonEmpty = %q, want first", got)
	}
	if got := FirstNonEmpty(nil, ""); got != "" {
		t.Errorf("FirstNonEmpty(all empty) = %q, want empty", got)
	}
}

func TestToFloat32(t *testing.T) {
	cases := []struct {
		in   any
		want float32
	}{
		{float64(9.8), 9.8},
		{float32(1.5), 1.5},
		{7, 7},
		{int64(3), 3},
		{"nope", 0},
		{nil, 0},
	}
	for _, c := range cases {
		if got := ToFloat32(c.in); got != c.want {
			t.Errorf("ToFloat32(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestString(t *testing.T) {
	c, _ := gabs.ParseJSON([]byte(`{"a":"x","b":"","n":5}`))
	if got := String(c, "b", "a"); got != "x" {
		t.Errorf("String(b,a) = %q, want x (first non-empty)", got)
	}
	if got := String(c, "missing"); got != "" {
		t.Errorf("String(missing) = %q, want empty", got)
	}
	if got := String(nil, "a"); got != "" {
		t.Errorf("String(nil) = %q, want empty", got)
	}
}
