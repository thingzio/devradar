# Public Landing Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refresh the unauthenticated DevRadar landing page around continuous SBOM security posture and the maintainer decisions the shipped product supports.

**Architecture:** Keep `GET /` static and server-rendered. Replace stale marketing copy and generic feature cards in the existing template, add a responsive semantic posture loop using existing CSS tokens, and preserve the current authentication handler and form states unchanged.

**Tech Stack:** Go 1.26, `html/template`, existing embedded CSS, stdlib HTTP tests.

## Global Constraints

- The primary reader is an open-source maintainer who also performs platform and security work.
- Lead with “Continuous security posture for every image you ship.”
- Describe current browser alerts as opt-in in-product alerts; do not advertise email or webhook delivery.
- Never claim that a digest is safe or that DevRadar proves SBOM authenticity, runtime reachability, or compatibility.
- Preserve GitHub OAuth, magic-link, sent, error, rate-limit, session-redirect, and signed-out navigation behavior.
- Use the existing palette, system typography, dark mode, focus treatment, and controls; add no dependency, JavaScript behavior, image, fake metric, gradient, or marketing font.
- Render the posture loop horizontally on wide screens and vertically on narrow screens.
- No deployment or release.

---

### Task 1: Maintainer-first public landing page

**Files:**
- Modify: `pkg/server/landing_test.go`
- Modify: `pkg/server/templates/landing.html`
- Modify: `pkg/server/static/css/app.css`
- Modify: `pkg/server/templates/_chrome.html`
- Modify: `pkg/server/ui.go`

**Interfaces:**
- Consumes: existing `handleLanding`, `.Error`, `.Sent`, `.GitHubOAuth`, `.SignedIn`, `.Version`, and `POST /auth/login` contract.
- Produces: the unchanged public `GET /` route with current product copy and a responsive `.posture-loop` presentation.

- [ ] **Step 1: Replace the landing marketing test with the current product contract**

Update `TestLanding_RendersMarketing` so it requires the hero, five evidence stages, four maintainer questions, supporting capabilities, trust boundary, and sign-in form. It must also reject stale/deferred claims and authenticated navigation:

```go
for _, want := range []string{
	"Continuous security posture for every image you ship",
	"Submit", "Detect", "Prioritize", "Compare", "Trend",
	"What changed, and why?",
	"What should I fix next?",
	"Is the next tracked digest better?",
	"Is my fleet improving?",
	"Opt-in browser alerts",
	"Grype and Trivy",
	"License policy", "OpenVEX", "tenant-scoped API",
	`action="/auth/login"`,
	"honest note on trust",
} {
	if !strings.Contains(body, want) {
		t.Errorf("landing page missing %q", want)
	}
}
for _, stale := range []string{"Coming soon", "Push & email alerts", "webhook delivery", "universally safe"} {
	if strings.Contains(body, stale) {
		t.Errorf("landing page contains stale or unsafe claim %q", stale)
	}
}
if strings.Contains(body, `class="tab `) {
	t.Error("signed-out landing must not render authed nav tabs")
}
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
go test ./pkg/server -run 'TestLanding_RendersMarketing|TestGitHubOAuth_LandingButton' -count=1
```

Expected: `TestLanding_RendersMarketing` fails because the new hero and maintainer-question copy do not exist; the OAuth test remains green.

- [ ] **Step 3: Replace stale template content while preserving authentication states**

Keep the complete existing `.hero-signin` block—including every `.Error`, `.Sent`, GitHub OAuth, and magic-link branch—functionally unchanged. Replace the hero copy with:

```html
<h1 class="hero-title">Continuous security posture for every image you ship.</h1>
<p class="hero-sub">Turn a digest-pinned SBOM into continuously refreshed, explainable work: what changed, why it changed, what to fix next, and whether a newer tracked digest has fewer relevant findings.</p>
```

Add the signature loop as a semantic ordered list:

```html
<section class="lp-section posture-section" aria-labelledby="posture-loop-title">
  <div class="lp-section-head">
    <p class="lp-eyebrow">The evidence loop</p>
    <h2 class="lp-h2" id="posture-loop-title">From SBOM to better decisions</h2>
  </div>
  <ol class="posture-loop">
    <li><span class="posture-step">Submit</span><code>SBOM</code><p>Pin immutable package inventory to an image digest.</p></li>
    <li><span class="posture-step">Detect</span><code>EVENT</code><p>See what changed and whether image inventory, vulnerability data, or tooling caused it.</p></li>
    <li><span class="posture-step">Prioritize</span><code>WORK</code><p>Order work by KEV, fix availability, severity, EPSS, blast radius, and age.</p></li>
    <li><span class="posture-step">Compare</span><code>DIGEST</code><p>Inspect exact vulnerability, package, and license differences between releases.</p></li>
    <li><span class="posture-step">Trend</span><code>SNAPSHOT</code><p>Track observed vulnerability debt without inventing historical data.</p></li>
  </ol>
</section>
```

Replace “DevRadar Features” with four `.decision-card` sections titled exactly as the test requires. Their copy must cover opt-in browser alerts and causal timelines; transparent deterministic work ranking; conservative digest comparison using “fewer relevant findings”; and observed tenant trends beginning at the first snapshot.

Add “Built for real projects” capability cells for SBOM/private-registry operation, Grype and Trivy, license policy and OpenVEX, labels, and the tenant-scoped API/CI workflow. Reduce setup to sign in, submit with `devradarctl` or the API, and act in the browser. Retain the trust note and closing sign-in CTA. Delete the complete “Coming soon” section.

- [ ] **Step 4: Add the responsive evidence-loop presentation**

In the landing section of `pkg/server/static/css/app.css`, add only landing-scoped selectors using existing tokens:

```css
.lp-section-head { margin-bottom: 1.25rem; }
.lp-eyebrow { color: var(--accent); font-family: var(--font-mono); font-size: 0.72rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; }
.posture-loop { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); list-style: none; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); overflow: hidden; }
.posture-loop li { position: relative; min-width: 0; padding: 1.1rem; border-right: 1px solid var(--border); }
.posture-loop li:last-child { border-right: 0; }
.posture-loop li:not(:last-child)::after { content: "→"; position: absolute; top: 1rem; right: -0.55rem; z-index: 1; width: 1.1rem; color: var(--accent); background: var(--surface); text-align: center; }
.posture-step { display: block; font-weight: 700; }
.posture-loop code { display: inline-block; margin: 0.45rem 0; color: var(--accent); font-family: var(--font-mono); font-size: 0.68rem; letter-spacing: 0.06em; }
.posture-loop p { color: var(--muted); font-size: 0.86rem; line-height: 1.45; }
.decision-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
```

Extend the existing `@media (max-width: 820px)` landing rule so `.posture-loop` becomes one column, stage borders become bottom borders, arrows become downward arrows, and `.decision-grid` becomes one column. Preserve readable focus states and do not introduce motion.

- [ ] **Step 5: Align page title and metadata with continuous posture**

In `handleLanding`, set:

```go
"Title": "Continuous SBOM security posture",
```

Update the static description in `_chrome.html` to:

```html
<meta name="description" content="Continuous SBOM security posture for container images — detect change, prioritize remediation, compare digests, and track vulnerability debt.">
```

- [ ] **Step 6: Run focused tests and verify GREEN**

Run:

```bash
go test ./pkg/server -run 'TestLanding_RendersMarketing|TestGitHubOAuth_LandingButton' -count=1
```

Expected: both tests pass; the signed-out landing retains the form and optional OAuth button.

- [ ] **Step 7: Run the complete qualification gate**

Run:

```bash
make qualify
go build ./...
git diff --check
```

Expected: race-enabled repository tests pass, coverage remains at or above 45%, `go vet` and `golangci-lint` report zero issues, both binaries build, and the diff has no whitespace errors.

- [ ] **Step 8: Commit the landing refresh**

```bash
git add pkg/server/landing_test.go pkg/server/templates/landing.html pkg/server/static/css/app.css pkg/server/templates/_chrome.html pkg/server/ui.go
git commit -S -m "feat(ui): refresh continuous posture landing page"
```

## Unresolved Questions

None.
