# vectr — Implementation Reference

> High-level design: see [README.md](README.md)

## Overview

The corpus pipeline scans public container images from five registries daily, persists time-series vulnerability records, and computes deltas between scans. The pipeline is designed around a single core insight: **most images don't change day-to-day**. A digest-check gate before every pull collapses actual pull volume by 80–90%, which eliminates rate-limit pressure, reduces egress cost, and removes any ToS ambiguity with Docker Hub.

The execution model uses ephemeral GCE VMs built from a custom Ubuntu image with all scanners pre-installed and vulnerability databases pre-warmed. VMs pull work from a Cloud Tasks queue, process up to 100 images, and self-terminate. VM count scales with queue depth, not with corpus size.

---

## Registry Constraints

### Docker Hub (`registry-1.docker.io`)
- **Rate limit**: 100 pulls / 6h unauthenticated per IP; unlimited with paid subscription
- **Auth required**: No for public images, but a paid Docker Team subscription ($15/mo) is required at corpus scale to avoid per-IP limits and ToS gray area
- **Critical**: Docker Hub sits behind Cloudflare and performs ASN-level pattern detection. GCE VMs all egress from AS15169 (Google). Using ephemeral IPs to circumvent per-IP limits is detectable and violates the spirit of Docker's ToS. One paid account, authenticated, is the correct approach.
- **Multi-arch**: Each architecture counts as a separate pull. Pin to `linux/amd64` unless arch comparison is a product feature.

### GHCR (`ghcr.io`)
- **Rate limit**: No documented pull limit for public images. Observed burst limit ~44,000 req/min.
- **Auth required**: No for public images. Authenticate with a read-only PAT anyway for better error messages and to avoid any future anonymous IP throttling.
- **Billing**: Currently free for public image egress. GitHub has promised 30-day notice before any change.

### NVIDIA NGC (`nvcr.io`)
- **Rate limit**: Undocumented, IP-based. Observed throttling in high-volume Kubernetes scenarios.
- **Auth required**: Yes, always. Free NGC account + API key required for all pulls.
- **Size concern**: CUDA/PyTorch base images are 4–15 GB each. 150 images × 5 GB average = 750 GB/cycle naive. Digest-check gate is non-negotiable for this registry — scan on change only, not daily.
- **Auth method**: `echo $NGC_API_KEY | docker login nvcr.io --username '$oauthtoken' --password-stdin`

### CNCF / `registry.k8s.io` / `quay.io`
- **Rate limit**: No documented limits on public images for `registry.k8s.io`. Quay.io throttles heavy automated pulls but limits are undocumented.
- **Auth required**: No for public images.
- **Note**: CNCF project images are spread across registries. Each image's source registry must be resolved at corpus-build time and stored in the corpus metadata.

---

## Design Principles

**Digest-check before every pull.** A HEAD request against the registry manifest API returns the current digest without counting as a pull on Docker Hub and without transferring any image data. Compare against the stored digest. Only queue a pull when the digest has changed. At steady state this reduces pull volume from ~700/day to ~70–100/day.

**Pull by digest, not by tag.** Tags are mutable. `postgres:16` can silently move to a new underlying image. Always pull and record by digest (`image@sha256:...`). This is the foundation of the delta engine — a tag moving is itself a detectable event.

**Scanners and vulnerability DBs are baked into the VM image.** Scanner binaries and DB snapshots are embedded at image build time. Workers do not download scanner DBs at runtime. DB freshness is maintained by rebuilding the VM image nightly via Cloud Build.

**Work is queue-driven, not baked into the VM.** VMs pull tasks from Cloud Tasks at runtime. This decouples corpus management from execution, allows retry on failure, and enables dynamic scaling based on actual queue depth.

**VMs self-terminate after draining their work.** No long-running fleet. Each VM processes up to 100 images and then deletes itself. Cost is proportional to actual work done.

---

## Component Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Cloud Scheduler (nightly, 02:00 UTC)                   │
└─────────────────────┬───────────────────────────────────┘
                      │ triggers
┌─────────────────────▼───────────────────────────────────┐
│  Cloud Run Job: digest-checker                          │
│  - reads corpus from Turso                              │
│  - HEAD /v2/{image}/manifests/{tag} per image           │
│  - compares digest against stored value                 │
│  - enqueues changed images → Cloud Tasks                │
│  - updates corpus last_checked timestamp                │
└─────────────────────┬───────────────────────────────────┘
                      │ enqueues tasks
┌─────────────────────▼───────────────────────────────────┐
│  Cloud Tasks: scan-queue                                │
│  - one task per (image_ref, digest, scanners[])         │
│  - 3600s lease duration                                 │
│  - 3 retries with exponential backoff                   │
└─────────────────────┬───────────────────────────────────┘
                      │ triggers (queue depth > 0)
┌─────────────────────▼───────────────────────────────────┐
│  Cloud Function: vm-spawner                             │
│  - reads queue depth                                    │
│  - spawns ceil(depth / 100) GCE VMs                    │
│  - uses instance template (custom image)                │
│  - passes SCAN_QUEUE, RESULTS_BUCKET, GCE_ZONE via      │
│    instance metadata                                    │
└─────────────────────┬───────────────────────────────────┘
                      │ creates
┌─────────────────────▼───────────────────────────────────┐
│  GCE VM Fleet (ephemeral, e2-standard-2)                │
│  - pulls tasks from Cloud Tasks                         │
│  - docker pull image@digest                             │
│  - trivy scan → JSON                                    │
│  - grype scan → JSON                                    │
│  - upload results → GCS                                 │
│  - docker rmi (free disk)                               │
│  - self-terminate when queue empty or 100 pulls done    │
└─────────────────────┬───────────────────────────────────┘
                      │ writes raw results
┌─────────────────────▼───────────────────────────────────┐
│  GCS: vectr-scan-results/                               │
│  - trivy/{image_slug}/{digest}.json                     │
│  - grype/{image_slug}/{digest}.json                     │
└─────────────────────┬───────────────────────────────────┘
                      │ triggers (object finalize)
┌─────────────────────▼───────────────────────────────────┐
│  Cloud Function: result-ingestor                        │
│  - normalizes Trivy + Grype JSON into unified schema    │
│  - writes ScanRecord rows to Turso                      │
│  - computes delta against previous scan                 │
│  - writes ScanDelta rows to Turso                       │
│  - triggers alert delivery if delta is non-empty        │
└─────────────────────────────────────────────────────────┘
```

---

## VM Image Build (Packer)

The custom Ubuntu image is rebuilt nightly. Scanner versions are pinned. Vulnerability databases are pre-warmed so workers do zero DB downloads at runtime.

```hcl
# packer/vectr-scanner.pkr.hcl
packer {
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = "~> 1"
    }
  }
}

variable "project_id" { type = string }
variable "zone"       { default = "us-central1-a" }
variable "trivy_version" { default = "0.58.1" }
variable "grype_version" { default = "0.85.0" }

source "googlecompute" "vectr-scanner" {
  project_id          = var.project_id
  source_image_family = "ubuntu-2204-lts"
  zone                = var.zone
  machine_type        = "e2-standard-2"
  disk_size           = 100  # GB — large images need headroom
  image_name          = "vectr-scanner-{{timestamp}}"
  image_family        = "vectr-scanner"
  ssh_username        = "packer"
}

build {
  sources = ["source.googlecompute.vectr-scanner"]

  provisioner "shell" {
    inline = [
      # Docker
      "sudo apt-get update -qq",
      "sudo apt-get install -y docker.io jq curl wget ca-certificates",
      "sudo systemctl enable docker",
      "sudo usermod -aG docker packer",

      # Trivy — pinned version
      "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v${var.trivy_version}",

      # Grype — pinned version
      "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin v${var.grype_version}",

      # gcloud CLI (for self-termination and Secret Manager)
      "curl -sSL https://sdk.cloud.google.com | bash -s -- --disable-prompts --install-dir=/usr/local",
      "ln -s /usr/local/google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud",
      "ln -s /usr/local/google-cloud-sdk/bin/gsutil /usr/local/bin/gsutil",

      # Pre-warm vulnerability DBs — critical, do not skip
      "sudo -u packer trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db",
      "sudo -u packer trivy image --download-java-db-only",
      "sudo -u packer grype db update",

      # Install worker script
      "sudo mkdir -p /opt/vectr",
    ]
  }

  provisioner "file" {
    source      = "scripts/worker.sh"
    destination = "/tmp/worker.sh"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/worker.sh /opt/vectr/worker.sh",
      "sudo chmod +x /opt/vectr/worker.sh",
      # Startup script hook
      "echo '/opt/vectr/worker.sh >> /var/log/vectr-worker.log 2>&1' | sudo tee /etc/rc.local",
      "sudo chmod +x /etc/rc.local",
    ]
  }
}
```

---

## Digest Checker (Cloud Run Job)

Runs nightly before the scan window. Emits only changed images into the queue.

```go
// cmd/digest-checker/main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	cloudtasks "cloud.google.com/go/cloudtasks/apiv2"
	taskspb "cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
	"github.com/tursodatabase/libsql-client-go/libsql"
	"google.golang.org/protobuf/types/known/durationpb"
)

type CorpusImage struct {
	ID         string
	ImageRef   string // e.g. "docker.io/library/postgres:16"
	Registry   string // dockerhub | ghcr | nvcr | quay | k8s
	LastDigest string
}

type ScanTask struct {
	ImageRef string   `json:"image_ref"`
	Digest   string   `json:"digest"`
	Scanners []string `json:"scanners"`
}

func main() {
	ctx := context.Background()

	db, err := libsql.NewConnector(os.Getenv("TURSO_URL"), libsql.WithAuthToken(os.Getenv("TURSO_TOKEN")))
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}

	images, err := loadCorpus(ctx, db)
	if err != nil {
		log.Fatalf("load corpus: %v", err)
	}

	tasksClient, err := cloudtasks.NewClient(ctx)
	if err != nil {
		log.Fatalf("tasks client: %v", err)
	}
	defer tasksClient.Close()

	queuePath := fmt.Sprintf("projects/%s/locations/%s/queues/scan-queue",
		os.Getenv("GCP_PROJECT"), os.Getenv("GCP_REGION"))

	queued, skipped := 0, 0
	for _, img := range images {
		digest, err := fetchDigest(ctx, img)
		if err != nil {
			log.Printf("WARN digest fetch failed for %s: %v", img.ImageRef, err)
			continue
		}

		if digest == img.LastDigest {
			skipped++
			if err := updateCheckedAt(ctx, db, img.ID); err != nil {
				log.Printf("WARN update checked_at for %s: %v", img.ImageRef, err)
			}
			continue
		}

		task := ScanTask{
			ImageRef: img.ImageRef,
			Digest:   digest,
			Scanners: []string{"trivy", "grype"},
		}
		payload, _ := json.Marshal(task)

		_, err = tasksClient.CreateTask(ctx, &taskspb.CreateTaskRequest{
			Parent: queuePath,
			Task: &taskspb.Task{
				MessageType: &taskspb.Task_HttpRequest{
					HttpRequest: &taskspb.HttpRequest{
						HttpMethod: taskspb.HttpMethod_POST,
						Url:        "https://placeholder/", // unused — VM polls queue directly
						Body:       payload,
					},
				},
				DispatchDeadline: durationpb.New(3600 * time.Second),
			},
		})
		if err != nil {
			log.Printf("WARN enqueue %s: %v", img.ImageRef, err)
			continue
		}

		if err := updateDigest(ctx, db, img.ID, digest); err != nil {
			log.Printf("WARN update digest for %s: %v", img.ImageRef, err)
		}
		queued++
		log.Printf("queued %s digest=%s", img.ImageRef, digest[:16])
	}

	log.Printf("done: queued=%d skipped=%d total=%d", queued, skipped, len(images))
}

// fetchDigest issues a HEAD request against the registry manifest API.
// This does not count as a pull on Docker Hub.
func fetchDigest(ctx context.Context, img CorpusImage) (string, error) {
	token, err := registryToken(ctx, img)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}

	manifestURL := manifestURL(img.ImageRef)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, manifestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("no Docker-Content-Digest header")
	}
	return digest, nil
}
```

---

## Worker Script

Runs on VM startup. Pulls tasks from Cloud Tasks, executes both scanners, uploads results, self-terminates.

```bash
#!/usr/bin/env bash
# /opt/vectr/worker.sh
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
PROJECT=$(curl -sf "http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google")
ZONE=$(curl -sf "http://metadata.google.internal/computeMetadata/v1/instance/zone" -H "Metadata-Flavor: Google" | awk -F/ '{print $NF}')
INSTANCE=$(curl -sf "http://metadata.google.internal/computeMetadata/v1/instance/name" -H "Metadata-Flavor: Google")
QUEUE=$(curl -sf "http://metadata.google.internal/computeMetadata/v1/instance/attributes/scan-queue" -H "Metadata-Flavor: Google")
BUCKET=$(curl -sf "http://metadata.google.internal/computeMetadata/v1/instance/attributes/results-bucket" -H "Metadata-Flavor: Google")
REGION=$(curl -sf "http://metadata.google.internal/computeMetadata/v1/instance/attributes/region" -H "Metadata-Flavor: Google")

QUEUE_PATH="projects/${PROJECT}/locations/${REGION}/queues/${QUEUE}"
MAX_PULLS=100
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# ── Registry auth ─────────────────────────────────────────────────────────────
setup_auth() {
  # Docker Hub — paid account credentials from Secret Manager
  DH_USER=$(gcloud secrets versions access latest --secret=dockerhub-username --project="$PROJECT")
  DH_TOKEN=$(gcloud secrets versions access latest --secret=dockerhub-token --project="$PROJECT")
  echo "$DH_TOKEN" | docker login --username "$DH_USER" --password-stdin registry-1.docker.io

  # GHCR — read-only PAT
  GHCR_PAT=$(gcloud secrets versions access latest --secret=ghcr-pat --project="$PROJECT")
  echo "$GHCR_PAT" | docker login --username vectr-scanner --password-stdin ghcr.io

  # NVCR — NGC API key
  NGC_KEY=$(gcloud secrets versions access latest --secret=ngc-api-key --project="$PROJECT")
  echo "$NGC_KEY" | docker login --username '$oauthtoken' --password-stdin nvcr.io
}

# ── Scan one image ────────────────────────────────────────────────────────────
scan_image() {
  local image_ref="$1"
  local digest="$2"
  local scanners="$3"  # JSON array: ["trivy","grype"]

  local pull_ref="${image_ref}@${digest}"
  local slug
  slug=$(echo "$image_ref" | tr '/:' '___')
  local short_digest="${digest#sha256:}"
  short_digest="${short_digest:0:12}"

  log "pulling ${pull_ref}"
  if ! docker pull --platform linux/amd64 "$pull_ref" 2>&1; then
    log "ERROR: pull failed for ${pull_ref}"
    return 1
  fi

  # Trivy
  if echo "$scanners" | jq -e '.[] | select(. == "trivy")' > /dev/null 2>&1; then
    local trivy_out="${WORK_DIR}/trivy_${slug}_${short_digest}.json"
    trivy image \
      --scanners vuln \
      --format json \
      --skip-db-update \
      --skip-java-db-update \
      --output "$trivy_out" \
      "$pull_ref" 2>&1 || log "WARN: trivy failed for ${pull_ref}"

    if [[ -f "$trivy_out" ]]; then
      gsutil -q cp "$trivy_out" \
        "gs://${BUCKET}/trivy/${slug}/${digest}.json"
    fi
  fi

  # Grype
  if echo "$scanners" | jq -e '.[] | select(. == "grype")' > /dev/null 2>&1; then
    local grype_out="${WORK_DIR}/grype_${slug}_${short_digest}.json"
    grype "$pull_ref" \
      --output json \
      --file "$grype_out" 2>&1 || log "WARN: grype failed for ${pull_ref}"

    if [[ -f "$grype_out" ]]; then
      gsutil -q cp "$grype_out" \
        "gs://${BUCKET}/grype/${slug}/${digest}.json"
    fi
  fi

  # Free disk — GPU images are large
  docker rmi "$pull_ref" 2>/dev/null || true
}

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# ── Main loop ─────────────────────────────────────────────────────────────────
main() {
  setup_auth

  local count=0

  while [[ $count -lt $MAX_PULLS ]]; do
    # Lease one task (3600s hold)
    local task_json
    task_json=$(gcloud tasks lease-tasks \
      --queue="$QUEUE" \
      --location="$REGION" \
      --project="$PROJECT" \
      --max-tasks=1 \
      --lease-duration=3600s \
      --format=json 2>/dev/null || echo "[]")

    if [[ "$(echo "$task_json" | jq length)" -eq 0 ]]; then
      log "queue empty, done"
      break
    fi

    local task_name image_ref digest scanners
    task_name=$(echo "$task_json" | jq -r '.[0].name')
    image_ref=$(echo "$task_json" | jq -r '.[0].httpRequest.body' | base64 -d | jq -r '.image_ref')
    digest=$(echo "$task_json" | jq -r '.[0].httpRequest.body' | base64 -d | jq -r '.digest')
    scanners=$(echo "$task_json" | jq -r '.[0].httpRequest.body' | base64 -d | jq -r '.scanners')

    log "processing [${count}/${MAX_PULLS}] ${image_ref}@${digest:7:12}"

    if scan_image "$image_ref" "$digest" "$scanners"; then
      gcloud tasks acknowledge "$task_name" \
        --queue="$QUEUE" \
        --location="$REGION" \
        --project="$PROJECT" 2>/dev/null || true
    else
      log "WARN: scan failed, leaving task for retry"
    fi

    ((count++))
  done

  log "processed ${count} images, self-terminating"
  gcloud compute instances delete "$INSTANCE" \
    --zone="$ZONE" \
    --project="$PROJECT" \
    --quiet
}

main "$@"
```

---

## VM Spawner (Cloud Function)

Triggered by Cloud Tasks queue depth crossing zero. Spawns the minimum number of VMs to drain the queue.

```go
// cmd/vm-spawner/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"

	cloudtasks "cloud.google.com/go/cloudtasks/apiv2"
	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/protobuf/proto"
)

const maxPullsPerVM = 100

func Spawn(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	project := os.Getenv("GCP_PROJECT")
	region  := os.Getenv("GCP_REGION")
	zone    := os.Getenv("GCP_ZONE")
	queue   := os.Getenv("SCAN_QUEUE")
	bucket  := os.Getenv("RESULTS_BUCKET")
	tmpl    := os.Getenv("INSTANCE_TEMPLATE") // projects/.../global/instanceTemplates/vectr-scanner

	// Get queue depth
	tasksClient, err := cloudtasks.NewClient(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer tasksClient.Close()

	queuePath := fmt.Sprintf("projects/%s/locations/%s/queues/%s", project, region, queue)
	queueInfo, err := tasksClient.GetQueue(ctx, &taskspb.GetQueueRequest{Name: queuePath})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	depth := int(queueInfo.Stats.TasksCount)
	if depth == 0 {
		log.Println("queue empty, no VMs needed")
		w.WriteHeader(http.StatusOK)
		return
	}

	vmCount := int(math.Ceil(float64(depth) / float64(maxPullsPerVM)))
	log.Printf("queue depth=%d, spawning %d VMs", depth, vmCount)

	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer instancesClient.Close()

	for i := range vmCount {
		name := fmt.Sprintf("vectr-worker-%d-%d", time.Now().Unix(), i)
		_, err := instancesClient.Insert(ctx, &computepb.InsertInstanceRequest{
			Project: project,
			Zone:    zone,
			InstanceResource: &computepb.Instance{
				Name: proto.String(name),
				Metadata: &computepb.Metadata{
					Items: []*computepb.Items{
						{Key: proto.String("scan-queue"),      Value: proto.String(queue)},
						{Key: proto.String("results-bucket"), Value: proto.String(bucket)},
						{Key: proto.String("region"),         Value: proto.String(region)},
					},
				},
			},
			SourceInstanceTemplate: proto.String(tmpl),
		})
		if err != nil {
			log.Printf("WARN spawn VM %s: %v", name, err)
			continue
		}
		log.Printf("spawned %s", name)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "spawned %d VMs for %d tasks\n", vmCount, depth)
}
```

---

## Result Ingestor (Cloud Function, GCS trigger)

Normalizes scanner JSON into the unified ScanRecord schema and computes deltas.

```go
// cmd/result-ingestor/main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/storage"
)

// ── Unified schema ────────────────────────────────────────────────────────────

type Finding struct {
	CVEID    string   `json:"cve_id"`
	Severity string   `json:"severity"`   // CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	FixedIn  string   `json:"fixed_in"`   // empty if no fix available
	CVSSScore float64 `json:"cvss_score"`
	Scanners []string `json:"scanners"`   // which scanners reported this CVE
}

type ScanRecord struct {
	ImageRef      string    `json:"image_ref"`
	Digest        string    `json:"digest"`
	Scanner       string    `json:"scanner"`
	ScannedAt     time.Time `json:"scanned_at"`
	SchemaVersion string    `json:"schema_version"`
	Findings      []Finding `json:"findings"`
}

type ScanDelta struct {
	ImageRef   string    `json:"image_ref"`
	FromDigest string    `json:"from_digest"`
	ToDigest   string    `json:"to_digest"`
	FromScan   time.Time `json:"from_scan"`
	ToScan     time.Time `json:"to_scan"`
	Scanner    string    `json:"scanner"`
	Added      []Finding `json:"added"`
	Removed    []Finding `json:"removed"`
	Changed    []Finding `json:"changed"`
	NetDelta   int       `json:"net_delta"` // positive = worse, negative = improved
}

// ── Trivy normalizer ──────────────────────────────────────────────────────────

type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string  `json:"VulnerabilityID"`
			PkgName         string  `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion    string  `json:"FixedVersion"`
			Severity        string  `json:"Severity"`
			CVSS            struct {
				Nvd struct {
					V3Score float64 `json:"V3Score"`
				} `json:"nvd"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func normalizeTrivy(data []byte, imageRef, digest string) (*ScanRecord, error) {
	var r trivyReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	rec := &ScanRecord{
		ImageRef:      imageRef,
		Digest:        digest,
		Scanner:       "trivy",
		ScannedAt:     time.Now().UTC(),
		SchemaVersion: "1",
	}

	seen := map[string]*Finding{}
	for _, result := range r.Results {
		for _, v := range result.Vulnerabilities {
			key := v.VulnerabilityID + "|" + v.PkgName
			if _, exists := seen[key]; exists {
				continue
			}
			f := Finding{
				CVEID:     v.VulnerabilityID,
				Severity:  strings.ToUpper(v.Severity),
				Package:   v.PkgName,
				Version:   v.InstalledVersion,
				FixedIn:   v.FixedVersion,
				CVSSScore: v.CVSS.Nvd.V3Score,
				Scanners:  []string{"trivy"},
			}
			seen[key] = &f
			rec.Findings = append(rec.Findings, f)
		}
	}
	return rec, nil
}

// ── Grype normalizer ──────────────────────────────────────────────────────────

type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID          string  `json:"id"`
			Severity    string  `json:"severity"`
			CVSSs       []struct {
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			} `json:"cvss"`
			Fix struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

func normalizeGrype(data []byte, imageRef, digest string) (*ScanRecord, error) {
	var r grypeReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	rec := &ScanRecord{
		ImageRef:      imageRef,
		Digest:        digest,
		Scanner:       "grype",
		ScannedAt:     time.Now().UTC(),
		SchemaVersion: "1",
	}

	for _, m := range r.Matches {
		fixedIn := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixedIn = m.Vulnerability.Fix.Versions[0]
		}
		score := 0.0
		if len(m.Vulnerability.CVSSs) > 0 {
			score = m.Vulnerability.CVSSs[0].Metrics.BaseScore
		}
		rec.Findings = append(rec.Findings, Finding{
			CVEID:     m.Vulnerability.ID,
			Severity:  strings.ToUpper(m.Vulnerability.Severity),
			Package:   m.Artifact.Name,
			Version:   m.Artifact.Version,
			FixedIn:   fixedIn,
			CVSSScore: score,
			Scanners:  []string{"grype"},
		})
	}
	return rec, nil
}

// ── GCS trigger handler ───────────────────────────────────────────────────────

type GCSEvent struct {
	Bucket string `json:"bucket"`
	Name   string `json:"name"` // e.g. "trivy/docker.io___library___postgres___16/sha256:abc123.json"
}

func Ingest(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	var event GCSEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	// Parse path: {scanner}/{slug}/{digest}.json
	parts := strings.SplitN(event.Name, "/", 3)
	if len(parts) != 3 {
		log.Printf("unexpected GCS path: %s", event.Name)
		w.WriteHeader(http.StatusOK)
		return
	}
	scanner := parts[0]
	slug    := parts[1]
	digestFile := strings.TrimSuffix(parts[2], ".json")
	imageRef := strings.ReplaceAll(slug, "___", "/")

	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer gcsClient.Close()

	obj := gcsClient.Bucket(event.Bucket).Object(event.Name)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	var record *ScanRecord
	switch scanner {
	case "trivy":
		record, err = normalizeTrivy(data, imageRef, digestFile)
	case "grype":
		record, err = normalizeGrype(data, imageRef, digestFile)
	default:
		log.Printf("unknown scanner: %s", scanner)
		w.WriteHeader(http.StatusOK)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("normalize: %v", err), 500)
		return
	}

	// TODO: persist record to Turso, compute delta, trigger alerts
	log.Printf("ingested %s/%s: %d findings", scanner, imageRef, len(record.Findings))
	w.WriteHeader(http.StatusOK)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.HandleFunc("/", Ingest)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
```

---

## Infrastructure (Terraform)

```hcl
# infra/main.tf

variable "project_id" {}
variable "region"     { default = "us-central1" }
variable "zone"       { default = "us-central1-a" }

# GCS — scan results
resource "google_storage_bucket" "scan_results" {
  name          = "${var.project_id}-vectr-scan-results"
  location      = var.region
  force_destroy = false

  lifecycle_rule {
    action { type = "Delete" }
    # raw scanner JSON kept 90 days; normalized data lives in Turso
    condition { age = 90 }
  }
}

# Cloud Tasks — scan queue
resource "google_cloud_tasks_queue" "scan_queue" {
  name     = "scan-queue"
  location = var.region

  retry_config {
    max_attempts  = 3
    min_backoff   = "30s"
    max_backoff   = "600s"
    max_doublings = 4
  }

  rate_limits {
    max_dispatches_per_second = 10
    max_concurrent_dispatches = 50
  }
}

# Secret Manager — registry credentials
resource "google_secret_manager_secret" "dockerhub_username" {
  secret_id = "dockerhub-username"
  replication { auto {} }
}
resource "google_secret_manager_secret" "dockerhub_token" {
  secret_id = "dockerhub-token"
  replication { auto {} }
}
resource "google_secret_manager_secret" "ghcr_pat" {
  secret_id = "ghcr-pat"
  replication { auto {} }
}
resource "google_secret_manager_secret" "ngc_api_key" {
  secret_id = "ngc-api-key"
  replication { auto {} }
}

# Service account for scan VMs
resource "google_service_account" "scanner" {
  account_id   = "vectr-scanner"
  display_name = "vectr Scanner VM"
}

resource "google_project_iam_member" "scanner_tasks" {
  project = var.project_id
  role    = "roles/cloudtasks.enqueuer"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}
resource "google_project_iam_member" "scanner_gcs" {
  project = var.project_id
  role    = "roles/storage.objectCreator"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}
resource "google_project_iam_member" "scanner_secrets" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}
resource "google_project_iam_member" "scanner_compute" {
  # needed for self-termination
  project = var.project_id
  role    = "roles/compute.instanceAdmin.v1"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

# Instance template — references the Packer-built image family
resource "google_compute_instance_template" "scanner" {
  name_prefix  = "vectr-scanner-"
  machine_type = "e2-standard-2"

  disk {
    source_image = "projects/${var.project_id}/global/images/family/vectr-scanner"
    auto_delete  = true
    boot         = true
    disk_size_gb = 100
    disk_type    = "pd-ssd"
  }

  network_interface {
    network = "default"
    access_config {} # ephemeral public IP — each VM gets a distinct IP
  }

  service_account {
    email  = google_service_account.scanner.email
    scopes = ["cloud-platform"]
  }

  scheduling {
    preemptible        = true   # ~80% cheaper; worker retries handle preemptions
    automatic_restart  = false
    on_host_maintenance = "TERMINATE"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Cloud Scheduler — nightly digest check
resource "google_cloud_scheduler_job" "digest_check" {
  name      = "vectr-digest-check"
  region    = var.region
  schedule  = "0 2 * * *"  # 02:00 UTC daily
  time_zone = "UTC"

  http_target {
    uri         = google_cloud_run_v2_job.digest_checker.uri
    http_method = "POST"
    oidc_token {
      service_account_email = google_service_account.scanner.email
    }
  }
}
```

---

## Cost Model

At steady state (post-seed, digest-check gate active):

| Item | Quantity | Unit Cost | Monthly |
|------|----------|-----------|---------|
| Docker Hub Team subscription | 1 | $15/mo | $15 |
| Digest checks (HEAD requests) | 700/day × 30 | free | $0 |
| Changed images pulled / scanned | ~100/day × 30 = 3,000 | — | — |
| GCE e2-standard-2 (preemptible) | ~30 VM-hours/mo | $0.017/hr | ~$0.51 |
| GCS storage (raw JSON, 90-day TTL) | ~50 GB | $0.02/GB | $1.00 |
| GCS egress (upload only, intra-region) | negligible | — | $0 |
| Internet egress (image pulls) | 3,000 × 500 MB avg = 1.5 TB | $0.08/GB | ~$120 |
| Cloud Tasks | 3,000 tasks/mo | free tier | $0 |
| Cloud Run Job (digest checker) | 30 invocations | free tier | $0 |
| **Total** | | | **~$137/mo** |

Seed phase (first run, all ~1,450 images pulled once): approximately $300–400 in additional egress depending on NVCR image sizes. NVCR images should be seeded separately with a higher change-threshold — weekly digest checks rather than daily.

---

## Operational Notes

**Scanner version pinning**: Bake specific versions into the Packer image. Do not use `latest`. The Trivy CI compromise in February 2026 (TeamPCP / aqua-bot PAT theft) demonstrates that scanner supply chains are a real attack surface. Pin, verify checksums, rebuild the VM image when intentionally upgrading.

**Trivy DB freshness**: Pre-warmed DBs age. Rebuild the VM image nightly via Cloud Build trigger so workers always start with a DB less than 24h old. Workers use `--skip-db-update` to prevent runtime downloads.

**Disk pressure**: GPU images from NVCR can be 10–15 GB. The `docker rmi` after each scan is mandatory. e2-standard-2 with 100 GB pd-ssd gives headroom for ~6 large images in flight simultaneously. If scanning NVCR images in bulk, consider e2-standard-4 with 200 GB disk for that VM group.

**Preemption handling**: Preemptible VMs can be reclaimed with 30s notice. Cloud Tasks leases are 3600s. On preemption, the lease expires and the task is requeued automatically. No additional preemption handling is needed in the worker — the queue provides the retry guarantee.

**Self-termination IAM**: The scanner service account has `compute.instanceAdmin.v1` scoped to the project. Restrict this to a specific label or instance name prefix in production to limit blast radius.


## What Changes Architecturally

The pipeline splits into two permanently separated phases:

**Phase A — SBOM generation** (triggered by digest change, pulls the image once, never again)
```
digest changed → pull image → syft generate SBOM → store in GCS → delete image
```

**Phase B — Daily vulnerability scan** (no network, no pull, pure CPU)
```
daily cron → download SBOM from GCS → grype sbom:file.json → store findings in DB
```

Phase B runs completely offline. No registry contact, no rate limits, no egress cost, no Docker credentials needed. The only input is the SBOM file and the local vulnerability DB.

---

## SBOM Size Reality

Syft SBOM size is a function of package count, not image size. A 15 GB NVCR CUDA image and a 50 MB Alpine image with the same number of installed packages produce SBOMs of similar size.

Empirical ranges for CycloneDX JSON (the most compact machine-readable format):

| Image type | Packages | SBOM size (CycloneDX JSON) | Gzipped |
|---|---|---|---|
| Alpine minimal (`alpine:3.19`) | ~20 | ~30 KB | ~8 KB |
| Debian slim (`python:3.12-slim`) | ~100 | ~200 KB | ~45 KB |
| Ubuntu full (`ubuntu:22.04`) | ~400 | ~700 KB | ~150 KB |
| Node.js app image | ~600 | ~1.1 MB | ~220 KB |
| CUDA base (`nvcr.io/nvidia/cuda:12.x`) | ~800 | ~1.5 MB | ~300 KB |
| PyTorch full (`nvcr.io/nvidia/pytorch`) | ~1,200+ | ~2.5 MB | ~500 KB |

Corpus-weighted average: roughly **600 KB uncompressed, ~130 KB gzipped** per SBOM. GCS stores objects compressed transparently when you use `gsutil -z json`.

---

## GCS Storage Cost

### Seed corpus (1,450 images, one SBOM each)

```
1,450 images × 600 KB avg = 870 MB uncompressed
                           ≈ 190 MB gzipped

GCS Standard storage: $0.020/GB/month
190 MB × $0.020 = $0.004/month — essentially free
```

### After 1 year of digest-change SBOMs

Each image averages roughly one digest change per week for active images (nginx, postgres, python) and one per month for stable images (NVCR base images). Rough blended rate: ~2 digest changes/month per image.

```
1,450 images × 2 changes/month × 12 months = 34,800 SBOMs
34,800 × 600 KB = ~20 GB uncompressed
                 ≈ 4.4 GB gzipped

4.4 GB × $0.020 = $0.09/month after year one
```

**GCS is a rounding error.** Store uncompressed for simplicity — even at 20 GB/year it's $0.40/month.

---

## Compute Cost: Daily SBOM Scan

This is the key question. Scanning an SBOM with Grype is pure CPU — no I/O, no network. On an e2-standard-2 (2 vCPU, 8 GB):

- Grype scan of a 600 KB SBOM: ~2–4 seconds
- 1,450 images × 3 seconds = ~4,350 seconds = **72 minutes total**
- One VM, fully serial: done in just over an hour

You don't need a fleet for daily scans. One Cloud Run Job or one ephemeral VM handles the full corpus in a single run.

```
Option A: Cloud Run Job (recommended)
  2 vCPU, 4 GB RAM
  72 min × $0.000024/vCPU-second × 2 vCPU = ~$0.21/day = $6.30/month

Option B: e2-standard-2 preemptible GCE
  72 min × $0.017/hr = $0.020/day = $0.61/month
```

Cloud Run Jobs are cleaner here — no VM lifecycle management, no self-termination logic, scales to zero between runs.

---

## Vulnerability DB Download Cost

Both Grype and Trivy need a fresh vulnerability DB daily. This is the one remaining external dependency in Phase B.

- Grype DB: ~200–400 MB/day (incremental updates are smaller after first download)
- Trivy DB: ~150–300 MB/day

If you run both scanners daily: ~500 MB/day downloaded from GHCR/GitHub.

```
500 MB/day × 30 = 15 GB/month inbound
GCP inbound: free
```

No cost. Pre-warm in the Cloud Run Job container image and update at job start with `grype db update`.

---

## PostgreSQL Schema and Size

This is the most important sizing question. Let me work through it precisely.

### Schema

```sql
-- One row per unique image tag ever seen in corpus
CREATE TABLE images (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_ref   TEXT NOT NULL,                    -- docker.io/library/postgres:16
    registry    TEXT NOT NULL,                    -- dockerhub|ghcr|nvcr|quay|k8s
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (image_ref)
);

-- One row per unique digest observed (immutable — never updated)
CREATE TABLE image_digests (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_id    UUID NOT NULL REFERENCES images(id),
    digest      TEXT NOT NULL,                    -- sha256:abc123...
    sbom_gcs    TEXT NOT NULL,                    -- gs://bucket/sboms/...
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (image_id, digest)
);

-- One row per scanner per digest per day
-- This is the time-series core — append-only
CREATE TABLE scan_runs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    digest_id   UUID NOT NULL REFERENCES image_digests(id),
    scanner     TEXT NOT NULL,                    -- grype|trivy
    scanned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    db_version  TEXT NOT NULL,                    -- scanner DB version used
    finding_count INT NOT NULL,
    critical_count INT NOT NULL,
    high_count  INT NOT NULL,
    medium_count INT NOT NULL,
    low_count   INT NOT NULL
);

-- One row per CVE per scan_run — this is the bulk of the data
CREATE TABLE findings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id UUID NOT NULL REFERENCES scan_runs(id),
    cve_id      TEXT NOT NULL,                    -- CVE-2024-1234
    severity    TEXT NOT NULL,                    -- CRITICAL|HIGH|MEDIUM|LOW|NEGLIGIBLE
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    fixed_in    TEXT,                             -- NULL if no fix
    cvss_score  NUMERIC(4,1),
    INDEX (scan_run_id),
    INDEX (cve_id),
    INDEX (severity)
);

-- Pre-computed deltas between consecutive scans of same digest+scanner
-- Written by result-ingestor, read by API and alert delivery
CREATE TABLE scan_deltas (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_id        UUID NOT NULL REFERENCES images(id),
    scanner         TEXT NOT NULL,
    from_digest_id  UUID REFERENCES image_digests(id),  -- NULL for first scan
    to_digest_id    UUID NOT NULL REFERENCES image_digests(id),
    from_scan_id    UUID REFERENCES scan_runs(id),
    to_scan_id      UUID NOT NULL REFERENCES scan_runs(id),
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_count     INT NOT NULL DEFAULT 0,
    removed_count   INT NOT NULL DEFAULT 0,
    changed_count   INT NOT NULL DEFAULT 0,
    net_delta       INT NOT NULL DEFAULT 0,       -- positive=worse, negative=better
    added_json      JSONB,                        -- compact delta payload for alerts
    removed_json    JSONB,
    changed_json    JSONB
);

-- Partitioning: findings grows without bound, partition by month
-- PostgreSQL native partitioning
CREATE TABLE findings (
    ...
) PARTITION BY RANGE (scan_run_id);
-- or more naturally, denormalize scanned_at into findings for partition key:

-- Better: partition findings by month of scan
CREATE TABLE findings (
    id          UUID NOT NULL,
    scan_run_id UUID NOT NULL,
    scanned_at  TIMESTAMPTZ NOT NULL,  -- denormalized for partition key
    cve_id      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    fixed_in    TEXT,
    cvss_score  NUMERIC(4,1)
) PARTITION BY RANGE (scanned_at);

CREATE TABLE findings_2026_04 PARTITION OF findings
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
-- add monthly via pg_partman or a cron job
```

### Row Volume Calculation

The findings table dominates everything else by 2–3 orders of magnitude.

**Findings per scan:**

Average CVE count per image varies widely:
- Alpine minimal: ~20–40 findings
- Debian/Ubuntu based: ~80–200 findings
- Node.js image (npm deps): ~150–400 findings
- NVCR CUDA/PyTorch: ~300–600 findings

Corpus-weighted average: ~**150 findings per image per scanner**.

```
Daily findings rows:
  1,450 images × 2 scanners × 150 findings = 435,000 rows/day

Monthly: 435,000 × 30 = 13,050,000 rows/month
Annual:  435,000 × 365 = 158,775,000 rows/year (~159M rows)
```

**Row size in PostgreSQL:**

Each findings row: UUID(16) + UUID(16) + TIMESTAMPTZ(8) + TEXT×4(avg 60 bytes) + TEXT(15) + NUMERIC(4) = ~140 bytes raw + ~30 bytes overhead = ~170 bytes/row.

```
Year 1 findings table:
  159M rows × 170 bytes = ~27 GB raw data
  + indexes (3 indexes × ~30% of table) = ~8 GB
  Total findings: ~35 GB after year one

scan_runs table:
  1,450 × 2 × 365 = 1,058,500 rows/year × ~100 bytes = ~100 MB — negligible

scan_deltas:
  ~1,058,500 rows × ~500 bytes (with JSONB payloads) = ~500 MB/year

images + image_digests:
  1,450 images, maybe 10,000 unique digests over a year × ~200 bytes = ~2 MB — negligible

Total DB at end of year one: ~36 GB
Total DB at end of year two: ~70 GB (findings partitions allow dropping old data)
Total DB at end of year three: ~100 GB (steady state with 2-year retention)
```

---

## PostgreSQL Hosting Options on GCP

### Cloud SQL for PostgreSQL

| Tier | vCPU | RAM | Storage | Cost/month |
|---|---|---|---|---|
| `db-g1-small` | shared | 1.7 GB | 10 GB SSD | ~$25 |
| `db-custom-1-3840` | 1 | 3.75 GB | 50 GB SSD | ~$65 |
| `db-custom-2-7680` | 2 | 7.5 GB | 100 GB SSD | ~$130 |
| `db-custom-2-7680` | 2 | 7.5 GB | 200 GB SSD | ~$155 |

For vectr at year one (36 GB data):

- **Launch through month 6**: `db-custom-1-3840` with 50 GB SSD ($65/mo) — adequate for write volume of 435K rows/day and read patterns of the API
- **Month 6 through year 2**: `db-custom-2-7680` with 150 GB SSD ($145/mo) — as findings table grows and query complexity increases with the metrics layer
- **Year 2+**: evaluate whether to stay on Cloud SQL or move findings to a time-series-optimized store (TimescaleDB on GCE, or partition pruning on Cloud SQL is usually sufficient)

Storage autoscales on Cloud SQL — set a 50 GB floor, it will grow automatically.

### Alternative: Neon (serverless Postgres)

Worth considering for early stage. Scales to zero between the daily scan job and API queries. Free tier: 10 GB. Pro: $19/month for 50 GB. The branching feature is useful for testing schema migrations against production data. Weakness: cold start latency on the API matters for the admission controller path (Phase 3), but is fine for Phase 1–2.

---

## Revised Cost Model: SBOM Architecture

| Item | Monthly cost |
|---|---|
| Docker Hub Team subscription (Phase A pulls only) | $15 |
| GCE e2-standard-2 preemptible, Phase A (seed: ~10 hr; steady: ~2 hr/month) | ~$2 steady state |
| GCS SBOM storage (20 GB/year → ~1.7 GB/month growth) | ~$0.50 |
| GCS operations (reads for daily scan) | ~$0.05 |
| Cloud Run Job, Phase B daily scan (72 min/day × 2 vCPU) | ~$6 |
| Cloud SQL `db-custom-1-3840` + 50 GB SSD | ~$65 |
| Grype/Trivy DB downloads (15 GB/month inbound) | $0 |
| Cloud Scheduler + Cloud Tasks | <$1 |
| **Total** | **~$90/month** |

Compare to the original pull-every-day architecture: **~$137/month**. SBOM approach saves ~$47/month primarily from eliminated egress, and that gap grows as the corpus scales. At 5,000 images the pull-every-day model becomes untenable; the SBOM model scales linearly on compute only.

---

## One Important Caveat

Scanning an SBOM is more flexible and performant for periodic review of image security over time. However there is one accuracy tradeoff worth naming explicitly: **Syft generates the SBOM from the image at a point in time**. If a CVE is later found in a package that Syft didn't catalog (e.g., a statically linked binary, a language runtime embedded without a package manifest), the SBOM will miss it and daily re-scans against it will also miss it. Direct image scanning catches some of these through deeper heuristics.

For vectr's use case — tracking known CVE database changes against a fixed package inventory — this is acceptable. The SBOM is a faithful representation of what's in the image at pull time. New CVEs against known packages are caught correctly. The gap is only undiscovered packages in the original SBOM, which is a Syft accuracy question, not an architecture question.

The practical mitigation: when a digest changes and you pull anyway to generate a new SBOM, you get a fresh catalog from the latest Syft version, which may catalog packages the previous version missed. Scanner version upgrades propagate naturally through the corpus.