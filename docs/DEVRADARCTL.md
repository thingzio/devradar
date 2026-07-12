# devradarctl — CLI Reference

_Reference for the [`devradarctl`](https://github.com/thingzio/devradarctl) CLI.
Tracks devradarctl **v0.3.0**. Last updated 2026-07-12._

`devradarctl` is the command-line client for DevRadar. It generates and submits
SBOMs, and wraps the read API so you can inspect findings, images, licenses, and
change history — and **gate CI** on them — from the terminal. It is a separate
repo/release from the DevRadar service; this doc mirrors its surface so the
service repo has a single place to check what the CLI can drive.

The CLI is a thin client over the documented API contract (`/openapi.yaml`).
Anything the CLI cannot do well today is usually an API gap tracked in
[`API.md`](../API.md), not a CLI limitation.

## Install

```sh
# Homebrew (macOS/Linux)
brew install thingzio/tap/devradarctl

# Go
go install github.com/thingzio/devradarctl@latest
```

Or download a prebuilt binary from the
[releases page](https://github.com/thingzio/devradarctl/releases).

**Prerequisites.** Read commands (`images`, `licenses`, `sbom get/findings/…`,
`watch`) need only an API token. SBOM generation (`sbom generate`, `submit
--image`) additionally needs [`syft`](https://github.com/anchore/syft) on `PATH`.
Image digest resolution runs in-process using ambient Docker credentials — no
`crane` needed.

## Authentication & configuration

Authentication is a DevRadar API token (`dr_…`), minted on the **Tokens &
settings** page of the UI. Provide it via the `DEVRADAR_TOKEN` env var or piped
on stdin (keeps the secret out of the process table and shell history):

```sh
export DEVRADAR_TOKEN=dr_xxxxxxxxxxxxxxxxxxxxxxxx
# or
echo "$DEVRADAR_TOKEN" | devradarctl submit --image alpine:3.20
```

Global flags and their environment variables:

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--base-url` | `DEVRADAR_BASE_URL` | `https://devradar.thingz.io` | Service base URL |
| — | `DEVRADAR_TOKEN` | — | API token (or piped via stdin) |
| `--output`, `-o` | `DEVRADAR_OUTPUT` | `table` | Output format: `table` or `json` |
| `--label` | `DEVRADAR_LABELS` | — | Grouping label(s); repeatable |
| `--tag` | — | — | Image version (tag) to record |
| `--image-ref` | — | — | Digest-pinned image reference (file-submit mode) |
| `--attestation` | — | — | Path to a sigstore/cosign bundle to verify |
| `--syft-path` | `DEVRADAR_SYFT_PATH` | `syft` | Path to the syft binary |
| `--scope` | — | `all-layers` | syft cataloging scope |
| `--debug` | `DEVRADAR_DEBUG` | `false` | Debug logging |
| `--log-json` | `DEVRADAR_LOG_JSON` | `false` | Emit logs as JSON |

Read commands default to a human-readable table; use `-o json` for full,
paginated JSON (pipe into `jq`). Pass `--all` to walk every page rather than the
first.

## Commands

| Command | Purpose |
|---|---|
| `submit` | Submit an SBOM from a file or generated from an image |
| `sbom generate` | Create an all-layers CycloneDX SBOM for an image locally (via syft) |
| `sbom get` | Retrieve details for a submitted SBOM |
| `sbom findings` | Show vulnerability findings (supports CI gating flags) |
| `sbom events` | Show the change events for an SBOM |
| `sbom failures` | Inspect scan failures for an SBOM |
| `sbom licenses` | Show per-package license detail for an SBOM |
| `sbom archive` | Stop tracking an SBOM (prompts unless `--yes`) |
| `images list` | Risk-ranked fleet view (filterable) |
| `images timeline` | Per-image change history across digests |
| `images sboms` | List the SBOMs for an image |
| `licenses` | Fleet-wide license rollup |
| `vex submit` / `vex list` | Submit and list OpenVEX documents |
| `watch` | Poll for new change events until interrupted (Ctrl-C) |
| `completion` | Shell completion (bash, zsh, fish, powershell) |

### CI gating (`sbom findings`)

`sbom findings` turns the read API into a build gate. Combine `--exit-code` with
a threshold so the command exits non-zero when the threshold is breached:

| Flag | Effect |
|---|---|
| `--exit-code` | Exit non-zero when a threshold below is breached |
| `--fail-on <severity>` | Breach if any finding at/above this severity exists |
| `--max-critical N` | Breach if the critical count exceeds N |
| `--max-high N` | Breach if the high count exceeds N |
| `--max-medium N` | Breach if the medium count exceeds N |

## Examples

```sh
# Generate an all-layers CycloneDX SBOM to stdout
devradarctl sbom generate --image alpine:3.20

# Submit from an image (resolve digest + generate + upload in one step)
echo "$DEVRADAR_TOKEN" | devradarctl submit --image alpine:3.20 --label team-x --label prod

# Submit an existing SBOM file, pinned to a digest
DEVRADAR_TOKEN=dr_xxx devradarctl submit --file alpine.cdx.json --image-ref alpine@sha256:…

# Submit an image together with a cosign attestation (verified server-side)
devradarctl submit --image "$IMAGE" --attestation cosign.att.jsonl

# Risk-ranked fleet view, high+ only, filtered to a repo
devradarctl images list --min-severity high -q myrepo

# Gate CI: fail the build on any high-or-critical finding
devradarctl sbom findings "$SBOM_ID" --all --exit-code --fail-on high

# Watch an image for new change events, polling each minute
devradarctl watch --repo ghcr.io/acme/api --interval 1m
```

## Notes

- **Attestation verification is server-side.** The CLI only uploads the bundle;
  DevRadar verifies the signature and binds it to the subject digest. A failed or
  unconfigured check never rejects the submission and never changes findings —
  verification is additive (see the Trust Model in the top-level `CLAUDE.md`).
- **Local SBOM generation is `sbom generate`** (it moved out from under a bare
  `sbom` command in an earlier release).
- The CLI ships and versions independently of the DevRadar service. When the
  service contract changes (`/openapi.yaml`), the CLI is updated to match; this
  doc is refreshed alongside CLI releases.
