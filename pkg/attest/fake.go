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

package attest

import "context"

// Fake is a test Verifier that returns a canned Result (or error) without any
// cryptography. It lets ingest and handler tests exercise the verified / failed /
// error paths deterministically, with no network, keys, or fixture bundles.
type Fake struct {
	Result      *Result
	Err         error
	Unavailable bool // when true, Available() reports false
	// LastBundle / LastDigest capture the most recent Verify inputs for assertions.
	LastBundle    []byte
	LastDigest    string
	LastSBOMBytes []byte
	Calls         int
}

// Available reports the fake as usable unless explicitly disabled. Set Unavailable
// to simulate an unconfigured verifier.
func (f *Fake) Available() bool { return f != nil && !f.Unavailable }

// Verify records the inputs and returns the configured Result/Err. When Result
// is set and its SubjectDigest is empty, the requested subjectDigest is copied in
// so callers get a realistic evidence record without repeating themselves.
func (f *Fake) Verify(_ context.Context, sbomBytes []byte, subjectDigest string, bundle []byte) (*Result, error) {
	f.Calls++
	f.LastBundle = bundle
	f.LastDigest = subjectDigest
	f.LastSBOMBytes = sbomBytes
	if f.Err != nil {
		return nil, f.Err
	}
	if f.Result != nil && f.Result.SubjectDigest == "" {
		cp := *f.Result
		cp.SubjectDigest = subjectDigest
		return &cp, nil
	}
	return f.Result, nil
}
