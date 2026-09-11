# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/thingzio/devradar/security/advisories/new).
Please do not open a public issue for a suspected vulnerability.

Include, where you can: affected version or commit, a description of the impact,
and the smallest reproduction you have. A concrete reproduction is far more
useful than a description of one.

**What to expect.** This is a single-maintainer project, so the honest numbers
are: an acknowledgement within five business days, and an assessment of whether
the report is in scope within ten. There is no fix-time commitment. If a report
is valid and serious, it gets worked before anything else; if it is valid and
minor, it may wait. You will be told which. Credit is offered by default in the
advisory unless you ask otherwise.

If you have not heard back in ten business days, assume the notification was
missed rather than ignored, and email mark@chmarny.com.

## Supported versions

Only the latest release receives fixes, along with `main`. There are no
long-term support branches and no backports to older minors. Given the size of
the project, maintaining more than one supported line would mean doing both
badly.

## The hosted instance

https://devradar.thingz.io is a reference deployment run by the maintainer. A report against the
hosted instance is welcome through the same channel. Please do not test against
it in ways that would degrade it for other users or touch data that is not
yours — run a local instance instead (see
[CONTRIBUTING.md](CONTRIBUTING.md)). Testing against your own local deployment
is always in scope and always welcome.

## In scope

- Any path by which one tenant can read, infer, or modify another tenant's data.
  This is the most serious class of bug the project can have.
- Authentication flaws in the magic-link flow or OAuth: link reuse, links valid
  beyond their window, guessable tokens, or a way to act as another user.
- Parser-level attacks through uploaded SBOMs and scanner output. These are
  untrusted input by definition, and a malformed SPDX or CycloneDX document
  should never do more than fail cleanly.
- Anything that causes a finding to be silently dropped, suppressed, or
  misreported as fixed. A vulnerability tracker that under-reports is worse than
  one that is merely down, and a way to force that is a security bug.
- Mishandling of API tokens or OAuth secrets, including tokens accepted after
  revocation or beyond their expiry.
- Injection reachable through SBOM content, image metadata, or CVE enrichment
  data — including into prompts sent to the configured LLM, where the output is
  then trusted.
- Secrets or tokens leaking into logs, error messages, alert deliveries, or
  exported data.

## Out of scope

- Findings from automated scanners with no demonstrated impact on this codebase.
  A dependency CVE report is welcome, but please say why it is reachable here.
- Vulnerabilities in third-party services the project integrates with — report
  those to the service.
- Missing hardening headers, cookie flags, or TLS configuration on the hosted
  instance without a described attack. These are worth fixing and a plain issue
  is the right venue.
- Social engineering, physical access, and denial of service through sheer
  volume.
- Anything requiring a compromised maintainer machine or a malicious
  administrator of your own tenant.

## Disclosure

Coordinated. A fix is prepared privately, released, and the advisory published
with the details. If a report is being actively exploited, that timeline
compresses. Please give a reasonable window before publishing independently —
and if the response times above are not met, say so in the advisory thread
rather than waiting indefinitely.
