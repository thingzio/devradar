# Public Landing Page Refresh

Date: 2026-07-11

## Objective

Present DevRadar as continuous SBOM security posture for open-source maintainers. The page should explain the everyday decisions the product supports now: what changed, why it changed, what to fix next, whether a tracked digest improves posture, and whether vulnerability debt is moving in the right direction.

The page must feel pragmatic and evidence-driven. It should not read like a generic commercial security platform or advertise deferred delivery channels.

## Primary Audience

The primary reader is an open-source maintainer who also performs platform and security work. The page should remain credible to a dedicated platform or security engineer without optimizing for enterprise SecOps workflows in this release.

## Message Hierarchy

The hero leads with:

> Continuous security posture for every image you ship.

Supporting copy explains that DevRadar turns an immutable, digest-pinned SBOM into continuously refreshed and explainable work. It identifies what changed, why it changed, what deserves attention, and whether a newer tracked digest has fewer relevant findings.

The key differentiator remains SBOM-first operation: DevRadar never needs registry credentials or image access. The SBOM crosses the trust boundary, which gives maintainers coverage for private images while keeping matching evidence reproducible.

Browser alerts are described as opt-in in-product alerts. Email and webhook delivery are not advertised. The page must never claim that a digest is safe or that DevRadar proves SBOM authenticity, runtime reachability, or compatibility.

## Information Architecture

The existing two-column hero remains: value proposition on the left and passwordless sign-in on the right. Existing GitHub OAuth, magic-link, sent, and error states remain unchanged.

Immediately below the hero, a posture loop becomes the page's signature structure:

1. Submit — a digest-pinned SBOM is the immutable input.
2. Detect — scheduled Grype and Trivy matching produces causal change events.
3. Prioritize — KEV, fix availability, severity, EPSS, blast radius, and age order the work queue transparently.
4. Compare — immutable digests reveal added, resolved, re-rated, newly fixable, package, and license changes.
5. Trend — observed daily tenant snapshots show whether relevant vulnerability debt is improving or regressing.

The next section organizes current capability around four maintainer questions rather than a generic feature grid:

- What changed, and why?
- What should I fix next?
- Is the next tracked digest better?
- Is my fleet improving?

A “Built for real projects” section groups supporting capabilities: private-registry coverage without credentials, dual-scanner agreement, license inventory and policy, OpenVEX suppression, labels, tenant-scoped API access, and CI-native submission.

The setup section is reduced to three steps: sign in, submit through `devradarctl` or the API, and use the browser views to act on continuously refreshed evidence.

The trust note and closing sign-in call to action remain. The stale “Coming soon” section is removed.

## Visual Direction

The page stays within DevRadar's existing GitHub-aligned light/dark palette, system typography, spacing, and controls. It introduces no marketing-only font, illustration, gradient, product screenshot, fake metric, or JavaScript dependency.

The posture loop is the one deliberate visual signature. Each stage carries a verb, its evidence artifact, and the maintainer decision it enables. It renders as a horizontal trace on wide screens and a vertical trace on narrow screens. Monospace utility labels may identify concrete artifacts such as SBOM, CVE, digest, and snapshot; the surrounding prose uses the existing body face.

Capability sections remain quiet so the loop carries the visual emphasis. Existing color tokens communicate meaning: accent for navigation and evidence flow, danger for harmful exposure, warning for attention, and success for observed improvement. Color is never the only carrier of meaning.

## Behavior and Accessibility

`GET /` remains a static public route. A valid existing session continues to redirect to `/overview`. Sign-in submission, OAuth availability, authentication errors, and rate-limit feedback retain their current behavior.

The page must work without JavaScript, preserve visible keyboard focus, use semantic headings and ordered stages, remain readable in automatic dark mode, and collapse cleanly on mobile. It must not render authenticated navigation to signed-out visitors.

The page metadata should use the continuous-posture positioning instead of the older pull-only vulnerability-tracking description.

## Testing

Landing-route tests will assert:

- the continuous SBOM posture promise;
- the five-stage posture loop;
- the four maintainer questions;
- current browser alerts, work queue, comparison, trends, license/VEX, API, and CI capabilities;
- the trust boundary and absence of universal-safety claims;
- absence of deferred email/webhook and stale “coming soon” claims;
- preservation of the sign-in form, optional GitHub OAuth button, and signed-out navigation boundary.

No database-backed marketing metrics or production data are introduced.

## Out of Scope

- Product screenshots or live demo data.
- Persona-specific SecOps variants.
- Pricing, billing, testimonials, or competitive comparisons.
- Email, webhook, escalation, or external integration marketing.
- Analytics, tracking pixels, or third-party frontend dependencies.
