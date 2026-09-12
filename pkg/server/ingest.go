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

package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/thingzio/devradar/pkg/attest"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/sbom"
)

// maxSBOMBytes caps the decoded (and decompressed) SBOM size — untrusted input.
// Shared with the blob-read path (config.MaxSBOMBytes) so ingest and every
// later read enforce one invariant.
const maxSBOMBytes = config.MaxSBOMBytes

// sbomStatusPending is the transient ingest state of a row whose bytes have not
// yet been stored (see the pending→active lifecycle in handleSubmitSBOM).
const sbomStatusPending = "pending"

// maybeGunzip returns b unchanged unless it starts with the gzip magic bytes, in
// which case it decompresses through a reader bounded to limit+1 so a
// decompression bomb is rejected rather than exhausting memory.
func maybeGunzip(b []byte, limit int) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		return b, nil // not gzip
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("sbom gzip is invalid")
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("sbom gzip is corrupt")
	}
	if len(out) > limit {
		return nil, fmt.Errorf("sbom exceeds size limit after decompression")
	}
	return out, nil
}

// submitRequest is the POST /v1/sboms body. Only `sbom` is required; the rest
// are overrides for when the SBOM's self-reporting is weak.
type submitRequest struct {
	SBOM        string   `json:"sbom"`                   // base64-encoded bytes (required)
	ImageRef    string   `json:"image_ref,omitempty"`    // override the image reference
	Version     string   `json:"version,omitempty"`      // image tag (e.g. "v1.20.2"); else parsed from image_ref
	Labels      []string `json:"labels,omitempty"`       // tenant grouping labels (e.g. "team-x","prod")
	GeneratedAt string   `json:"generated_at,omitempty"` // RFC3339 override
	Attestation string   `json:"attestation,omitempty"`  // base64 sigstore bundle; verified if trust policy configured
}

type submitResponse struct {
	SBOMID             string `json:"sbom_id"`
	ImageRef           string `json:"image_ref"`
	Digest             string `json:"digest"`
	Format             string `json:"format"`
	Existing           bool   `json:"existing"`            // true if this SBOM was already stored
	VerificationStatus string `json:"verification_status"` // unverified | verified | failed
}

// maxAttestationBytes caps the decoded attestation bundle (untrusted input).
// Sigstore bundles are small (signature + cert chain + inclusion proof); 1 MiB
// is generous and keeps a hostile submitter from inflating the request.
const maxAttestationBytes = 1 << 20

// handleSubmitSBOM ingests an SBOM: validate, resolve subject, content-address,
// store bytes + row. Thin and idempotent; no scanning or conversion here.
func (s *Server) handleSubmitSBOM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acct := middleware.AccountFromContext(ctx)
	if acct == nil {
		logMutationDenied(r, "sbom.submit", "unauthenticated")
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	// Bound the request body before decode. The JSON envelope carries BOTH the
	// base64 SBOM (inflates ~4/3) AND, optionally, a base64 attestation bundle
	// (also ~4/3, capped at maxAttestationBytes decoded). The cap must budget for
	// both plus JSON key overhead, or a legitimate near-max SBOM submitted WITH an
	// attestation is wrongly rejected 413. MaxBytesReader (not LimitReader) so an
	// over-cap body is a real error we can map to 413, not a silent truncation that
	// later fails as bad JSON.
	const envelopeOverhead = 4096 // JSON keys, quoting, other small fields
	maxBody := int64(maxSBOMBytes)*4/3 + int64(maxAttestationBytes)*4/3 + envelopeOverhead
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			logMutationDenied(r, "sbom.submit", "request too large")
			writeError(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		logMutationDenied(r, "sbom.submit", "unreadable body")
		writeError(w, http.StatusBadRequest, "could not read request body")
		return
	}
	var req submitRequest
	if err := json.Unmarshal(body, &req); err != nil {
		logMutationDenied(r, "sbom.submit", "invalid JSON")
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.SBOM == "" {
		logMutationDenied(r, "sbom.submit", "missing SBOM")
		writeError(w, http.StatusBadRequest, "missing sbom")
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(req.SBOM)
	if err != nil {
		logMutationDenied(r, "sbom.submit", "invalid SBOM base64")
		writeError(w, http.StatusBadRequest, "sbom is not valid base64")
		return
	}
	// Accept gzip-compressed SBOMs, but decompress through a bounded reader so a
	// small compressed payload can't expand into a memory-exhausting bomb.
	raw, err := maybeGunzip(decoded, maxSBOMBytes)
	if err != nil {
		logMutationDenied(r, "sbom.submit", "invalid compressed SBOM")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(raw) > maxSBOMBytes {
		logMutationDenied(r, "sbom.submit", "SBOM too large")
		writeError(w, http.StatusRequestEntityTooLarge, "sbom exceeds size limit")
		return
	}
	if !json.Valid(raw) {
		logMutationDenied(r, "sbom.submit", "invalid SBOM JSON")
		writeError(w, http.StatusBadRequest, "sbom is not valid JSON (expected CycloneDX or SPDX)")
		return
	}

	// Resolve the subject from the SBOM; if it has no digest (e.g. generated by
	// tag), fall back to a digest parsed from the caller's image_ref.
	subj, err := sbom.ResolveWithRef(raw, req.ImageRef)
	if err != nil {
		logMutationDenied(r, "sbom.submit", "unresolvable SBOM subject")
		if errors.Is(err, sbom.ErrNoDigest) {
			writeError(w, http.StatusUnprocessableEntity,
				"could not resolve an image digest from the SBOM; generate it by digest "+
					"(image@sha256:...) or supply image_ref with an @sha256: digest")
			return
		}
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("cannot parse SBOM: %v", err))
		return
	}

	imageRef := subj.ImageRef
	if req.ImageRef != "" {
		imageRef = req.ImageRef // caller override wins for the label
	}
	// Split the effective ref into its stable grouping identity (repository) and
	// version (tag). The tag is often absent when submitters pin by digest, so
	// an explicit `version` in the request takes precedence.
	repository, refTag, _ := sbom.SplitRef(imageRef)
	version := req.Version
	if version == "" {
		version = refTag
	}

	generatedAt := subj.GeneratedAt
	if req.GeneratedAt != "" {
		if t, perr := time.Parse(time.RFC3339, req.GeneratedAt); perr == nil {
			generatedAt = t
		}
	}

	// Content-address per account: the id is sha256(tenant_id + bytes), not
	// sha256(bytes). A global content hash would collide across accounts — two
	// accounts submitting the same public image's SBOM would share one row (PK is
	// id), and the second submitter could never see "their" SBOM. Scoping by
	// account preserves per-account idempotency and dedup while keeping isolation.
	h := sha256.New()
	h.Write([]byte(acct.ID))
	h.Write([]byte{0}) // domain separator
	h.Write(raw)
	id := fmt.Sprintf("%x", h.Sum(nil))
	objectPath := fmt.Sprintf("gs://%s/%s/%s", config.SBOMBucket(), acct.ID, id)

	// Insert the pending row while holding the account lifecycle fence. It remains
	// invisible until the exact bytes are stored and activation succeeds below.
	effID, inserted, status, err := s.store.UpsertSBOMWithLimit(ctx, &postgres.SBOM{
		ID:           id,
		TenantID:     acct.ID,
		ImageRef:     imageRef,
		Repository:   repository,
		Version:      version,
		Digest:       subj.Digest,
		Format:       string(subj.Format),
		SpecVersion:  subj.SpecVersion,
		Tool:         subj.Tool,
		ToolVersion:  subj.ToolVersion,
		PackageCount: subj.PackageCount,
		ObjectPath:   objectPath,
		Labels:       normalizeLabels(req.Labels),
		GeneratedAt:  generatedAt,
	}, config.MaxSBOMsPerTenant(), config.MaxImagesPerTenant())
	if errors.Is(err, postgres.ErrImageLimit) {
		logMutationDenied(r, "sbom.submit", "image quota reached")
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf(
			"image limit reached (%d images per account); archive an image or contact support to raise the limit",
			config.MaxImagesPerTenant()))
		return
	}
	if errors.Is(err, postgres.ErrSBOMLimit) {
		logMutationDenied(r, "sbom.submit", "SBOM quota reached")
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf(
			"SBOM limit reached (%d active SBOMs per account); archive an SBOM or contact support to raise the limit",
			config.MaxSBOMsPerTenant()))
		return
	}
	if err != nil {
		logMutationFailure(r, "sbom.submit", acct.ID, id, err)
		writeError(w, http.StatusInternalServerError, "failed to record SBOM")
		return
	}

	// canonicalBytes is true only when `raw` are the bytes we are actually storing
	// under effID — a fresh insert, or a 'pending' row we are self-healing. On a
	// re-submit that resolves to an existing 'active' row (same digest+format,
	// possibly DIFFERENT bytes: by-tag vs by-digest generation, a newer generator),
	// the stored bytes are the ORIGINAL submitter's, not `raw`. Attestation
	// verification and license extraction must only ever run over the canonical
	// stored bytes — verifying `raw` and attaching the evidence to effID would
	// falsely claim the STORED SBOM was signed (a sbom-bytes binding over bytes we
	// never kept). See attestation trust model in CLAUDE.md.
	canonicalBytes := inserted || status == sbomStatusPending

	// Store bytes then activate, for a genuinely new SBOM OR one left 'pending' by
	// an earlier submission whose upload failed (self-heal). An existing 'active'
	// row's bytes are canonical and must not be rewritten. Upload-before-activate
	// guarantees an active row always has its bytes; a failure here deletes the
	// pending row so a retry starts clean (writes are content-addressed, so the
	// re-Put is idempotent).
	if canonicalBytes {
		if err := s.blobs.Put(ctx, objectPath, raw); err != nil {
			logMutationFailure(r, "sbom.submit", acct.ID, effID, err)
			slog.Error("store sbom bytes", "sbom_id", effID, "error", err)
			if delErr := s.store.DeletePendingSBOM(ctx, acct.ID, effID); delErr != nil {
				slog.Error("cleanup pending sbom", "sbom_id", effID, "error", delErr)
			}
			writeError(w, http.StatusInternalServerError, "failed to store SBOM")
			return
		}
		// Capture the per-package license inventory from the frozen SBOM. This is
		// additive to ingest: extraction and storage are best-effort and must never
		// fail the submission (a weak/absent license block is not a reason to reject
		// an otherwise-valid SBOM). Errors are recorded on the failure surface, not
		// returned. Licenses are immutable per digest, so this runs once, on insert.
		if pkgs := sbom.ExtractPackages(raw); len(pkgs) > 0 {
			if err := s.store.UpsertSBOMPackages(ctx, effID, pkgs); err != nil {
				slog.Error("store sbom packages", "sbom_id", effID, "error", err)
				s.store.RecordScanFailure(ctx, effID, "", "license-extract", err)
			}
		}
		// Promote to active only after the bytes are durably stored.
		if err := s.store.ActivateSBOMAudited(ctx, acct.ID, effID,
			middleware.ActorFromContext(ctx), middleware.RequestIDFromContext(ctx)); err != nil {
			logMutationFailure(r, "sbom.activate", acct.ID, effID, err)
			slog.Error("activate sbom", "sbom_id", effID, "error", err)
			if shouldCompensateSBOMActivation(err) {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				defer cancel()
				if delErr := s.blobs.Delete(cleanupCtx, objectPath); delErr != nil {
					slog.Error("cleanup terminal SBOM activation blob", "account_id", acct.ID,
						"sbom_id", effID, "object_path", objectPath, "error", delErr)
				} else if delErr := s.store.DeletePendingSBOM(cleanupCtx, acct.ID, effID); delErr != nil {
					slog.Error("cleanup terminal pending SBOM", "account_id", acct.ID,
						"sbom_id", effID, "error", delErr)
				}
			}
			writeError(w, http.StatusInternalServerError, "failed to activate SBOM")
			return
		}
	}

	// Verify an attestation only against the canonical stored bytes (see
	// canonicalBytes above). Best-effort and fully isolated (like license
	// extraction): a verifier error or a failed verification is recorded as
	// evidence and reflected in the response, but NEVER changes the 202 or fails
	// ingest. DevRadar's guarantee is determinism; authenticity is an additive
	// overlay. For a re-submit onto an existing SBOM we do NOT re-verify (the bytes
	// under effID are the original's, and re-verification is user-triggered only);
	// we report the STORED status so the response reflects the actual evidence.
	var verificationStatus string
	if canonicalBytes {
		verificationStatus = s.verifyAttestation(ctx, acct.ID, effID, raw, subj.Digest, req.Attestation)
	} else if st, err := s.store.GetVerificationStatus(ctx, acct.ID, effID); err == nil {
		verificationStatus = st
	} else {
		verificationStatus = attest.StatusUnverified
	}

	writeJSON(w, http.StatusAccepted, submitResponse{
		SBOMID: effID, ImageRef: imageRef, Digest: subj.Digest,
		Format: string(subj.Format), Existing: !inserted, VerificationStatus: verificationStatus,
	})
}

func shouldCompensateSBOMActivation(err error) bool {
	return errors.Is(err, postgres.ErrAccountInactive) || errors.Is(err, postgres.ErrNotFound)
}

// verifyAttestation runs attestation verification for a just-ingested SBOM and
// persists the evidence, returning the resulting verification_status for the
// response. It degrades to attest.StatusUnverified whenever verification is not
// configured, not requested, or cannot be completed — it never returns an error
// and never blocks ingest.
func (s *Server) verifyAttestation(ctx context.Context, tenantID, sbomID string, sbomBytes []byte, subjectDigest, attestationB64 string) string {
	if attestationB64 == "" || s.verifier == nil || !s.verifier.Available() {
		return attest.StatusUnverified
	}
	bundle, err := base64.StdEncoding.DecodeString(attestationB64)
	if err != nil {
		slog.Warn("attestation not valid base64", "sbom_id", sbomID,
			"request_id", middleware.RequestIDFromContext(ctx))
		return attest.StatusUnverified
	}
	if len(bundle) > maxAttestationBytes {
		slog.Warn("attestation exceeds size limit", "sbom_id", sbomID, "bytes", len(bundle),
			"request_id", middleware.RequestIDFromContext(ctx))
		return attest.StatusUnverified
	}

	res, err := s.verifier.Verify(ctx, sbomBytes, subjectDigest, bundle)
	if err != nil {
		// Could not run the check (malformed bundle, verifier fault): record a
		// failed result so the outcome is auditable, but never fail ingest.
		slog.Warn("attestation verification error", "sbom_id", sbomID,
			"request_id", middleware.RequestIDFromContext(ctx), "error", err)
		res = &attest.Result{
			Outcome: attest.ResultFailed, Mode: attest.ModeKeyless,
			Binding: attest.BindingImageDigest, SubjectDigest: subjectDigest,
			VerifierVersion: "unknown", PolicyVersion: "unknown",
			FailureReason: err.Error(), Envelope: bundle,
		}
	}
	if res == nil {
		return attest.StatusUnverified
	}
	if err := s.store.SaveAttestationAudited(ctx, tenantID, sbomID, res,
		middleware.ActorFromContext(ctx), middleware.RequestIDFromContext(ctx)); err != nil {
		slog.Error("persist attestation evidence", "sbom_id", sbomID,
			"request_id", middleware.RequestIDFromContext(ctx), "error", err)
		return attest.StatusUnverified
	}
	return res.Outcome
}

// normalizeLabels cleans tenant-supplied grouping labels: trim, lowercase, drop
// empties, dedupe, and bound count/length so an abusive submission can't bloat
// the row.
func normalizeLabels(in []string) []string {
	const maxLabels, maxLen = 20, 64
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, l := range in {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "" || len(l) > maxLen {
			continue
		}
		if _, dup := seen[l]; dup {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
		if len(out) >= maxLabels {
			break
		}
	}
	return out
}
