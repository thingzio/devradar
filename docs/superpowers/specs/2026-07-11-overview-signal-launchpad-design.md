# Overview Signal Launchpad

Date: 2026-07-11

## Objective

Update the authenticated `/overview` page so it reflects DevRadar's actionable-alert, work-queue, comparison, license, and posture-trend capabilities without duplicating their dedicated views.

The page remains a compact maintainer launchpad. It answers four high-level questions: what is urgent, what should be fixed next, whether posture is moving, and which deeper workflow deserves attention.

## Audience and Page Role

The primary user is an open-source maintainer who also performs platform and security work. `/overview` is the signed-in control plane, not an executive report and not a replacement for Work, Trends, Images, Alerts, or Licenses.

The page should expose enough evidence to choose the next action and then link to the canonical detail page.

## Information Hierarchy

The existing search and bounded unread-alert panel remain first. Alerts continue to degrade independently from image and finding data.

The current fleet metrics become an explicitly labeled “Current posture” section. It retains:

- active image repositories;
- canonical relevant findings;
- critical findings;
- distinct KEV exposures;
- percentage with a reported fix;
- latest scan freshness;
- severity and remediation-readiness charts.

Immediately after current posture, a compact action band adds:

1. **What needs attention** — the first three canonical work items in the existing deterministic order: KEV, fix availability, severity, EPSS, affected-image blast radius, then age. Every displayed item shows its ranking reasons and links to the CVE detail; the full queue remains at `/work`.
2. **Direction of travel** — the latest recorded tenant posture snapshot and its change from the preceding recorded snapshot. Adjacent dates may be called day-over-day; gaps name the exact comparison date. One point says “No prior snapshot”; no points say “Coverage begins with the first snapshot.” The card links to `/trends`.
3. **License policy** — the current fleet license-policy violation count. An empty policy says “No policy configured” and links to the Settings and Licenses workflows; it does not imply compliance. A configured policy links to `/licenses`.
4. **Compare releases** — the number of tenant repositories with at least two active, distinct digests. It links to `/dashboard`, where the maintainer selects a repository and exact digests. It does not invent a fleet-wide upgrade recommendation.

The existing highest-risk image preview remains below the action band.

## Data Boundaries

The work preview reuses `FleetCVEs` with risk-descending order and a limit of three. It must preserve canonical finding deduplication, scanner-agreement metadata, VEX annotations, and tenant scoping.

The trend preview reuses `TenantPostureTrend` with a bounded window. It reports only observed points and never reconstructs missing history.

The license preview reuses the tenant's read-time `LicensePolicy` and `FleetLicenseStats`; policy changes therefore apply immediately without rewriting frozen package inventory.

A focused Postgres read counts repositories with `COUNT(DISTINCT repository)` over active SBOM groups having at least two distinct digests. It accepts `tenantID` first and returns only a count.

## Failure Handling

The existing FleetStats and top-image reads remain the core page contract; failure returns the current overview error response.

Each new action-band signal is additive and best-effort. A work, trend, license, or comparison-count query failure must not hide current posture, alerts, charts, or top images. Its card says that the signal is temporarily unavailable and retains a link to the dedicated page where useful.

Empty states are explicit:

- no work items means no open findings meet the tenant threshold;
- no trend points means snapshot coverage has not started;
- one trend point means no prior snapshot is available;
- no license policy means no policy is configured, not zero violations;
- no comparison-ready repository invites the user to submit another digest.

## Visual Direction and Accessibility

Use the existing DevRadar palette, typography, cards, badges, and focus behavior. The action band is the only new structure: a two-column work preview paired with a narrow vertical stack of trend, license, and compare cards. It stacks into one column on small screens.

All cards use semantic headings and descriptive links. Ranking and change direction are stated in text; color is supplementary. No animation, client-side data fetch, new font, gradient, fake metric, or third-party dependency is introduced.

## Testing

Store and route coverage will verify:

- comparison-ready repository counts use distinct active digests and remain tenant-isolated;
- work preview is capped at three and follows the existing risk order;
- trend copy distinguishes adjacent dates, gaps, one point, and no points;
- license copy distinguishes an empty policy from a configured policy with zero violations;
- another tenant's work, snapshots, license inventory, and repositories never render;
- all cards link to their canonical detailed workflows;
- the overview never claims that an image or digest is safe, compatible, reachable, or compliant;
- the existing alert-unavailable degradation and no-images onboarding remain intact.

## Out of Scope

- Full work, alert, trend, license, or comparison tables on Overview.
- A fleet-wide upgrade recommendation without a selected baseline digest.
- Synthetic scores, inferred runtime risk, or reconstructed historical posture.
- New settings, notification channels, or per-user state.
