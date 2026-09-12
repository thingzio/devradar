# Contributing to devradar

Contributions are welcome, from typo fixes to new capabilities. This document
covers what you need to know before opening a pull request.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Project governance](#project-governance)
- [Developer Certificate of Origin](#developer-certificate-of-origin)
- [Getting started](#getting-started)
- [How to contribute](#how-to-contribute)
- [Pull request process](#pull-request-process)
- [Code style](#code-style)

## Code of Conduct

Be respectful and professional. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Project governance

This is a single-maintainer project. Decisions — what gets merged, what ships,
what is in scope — are the maintainer's, and the maintainer is listed in
[MAINTAINERS.md](MAINTAINERS.md). There is no steering committee and no vote,
because there are not enough people for either to mean anything.

**There is no review-time commitment.** A pull request may be reviewed the same
day or may sit for weeks. The project is maintained on a best-effort basis, and
pretending otherwise would set an expectation that gets broken. If something is
urgent for you, say so in the pull request — it helps with ordering, though it
is not a guarantee.

What this means in practice:

- **Small, focused pull requests get reviewed fastest.** A large change touching
  many packages is not refused, but it will wait longer.
- **Open an issue before a large change.** Finding out that a direction is wrong
  after a week of work is worse for you than for the project.
- **A closed pull request is not a judgment on you.** Scope is the most common
  reason; this is a reference implementation, not a product trying to satisfy
  everyone.

Adding a second maintainer is described in [MAINTAINERS.md](MAINTAINERS.md).
Short version: sustained, substantive contribution plus a willingness to take
the responsibility.

## Developer Certificate of Origin

This project requires the [Developer Certificate of
Origin](https://developercertificate.org) (DCO). It is not a CLA — you keep your
copyright, and you are not assigning anything. You are certifying that you wrote
the contribution or otherwise have the right to submit it under the project's
license.

Certify it by adding a `Signed-off-by` trailer to every commit:

```shell
git commit -s -m "feat: add the thing"
```

which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email must be real and must match your Git configuration. The DCO
bot checks every commit in a pull request and fails the check if any commit is
missing the trailer.

**`-s` and `-S` are different flags and this project wants both.** `-s` adds the
sign-off trailer described above. `-S` cryptographically signs the commit with
your key. Together:

```shell
git commit -S -s -m "feat: add the thing"
```

**If you forgot to sign off**, rewrite the commits on your branch and
force-push:

```shell
git rebase --signoff main
git push --force-with-lease
```

## Getting started

You need Go (the version in `go.mod`), Docker, and `make`. **You do not need a
Google Cloud account, and you do not need any credentials from the maintainer.**
If you hit a step that seems to require either, that is a bug — please file it.

```shell
git clone https://github.com/thingzio/devradar && cd devradar
make db-up        # start local Postgres via docker compose
make seed         # seed a test tenant
make test         # unit and integration tests with the race detector
make qualify      # the full gate: coverage, lint, govulncheck
make serve        # run the dev server
```

`make qualify` is the same gate CI runs. If it passes locally it should pass in
CI; if it does not, that is worth an issue.

> **Port 5432.** DevRadar, DevPulse, and DevTrace all bind 5432 in their own
> compose files, so only one of the three can run at a time. If `make db-up`
> fails to bind, run `docker compose down` in whichever sibling is up — the bind
> error does not say which project is holding the port.

See [DEVELOPMENT.md](DEVELOPMENT.md) for the longer tour: architecture, layout,
and day-to-day workflow.

## How to contribute

### Reporting bugs

> **Security vulnerabilities do not go here.** Report them privately through
> [GitHub Security Advisories](https://github.com/thingzio/devradar/security/advisories/new).
> See [SECURITY.md](SECURITY.md) for scope and expected response times.

Open an [issue](https://github.com/thingzio/devradar/issues/new/choose) and use
the bug template. The most useful bug report contains the smallest reproduction
you can manage — a failing test is ideal, a command with its output is good, a
description of the behavior is workable.

### Suggesting enhancements

Use the feature template. Lead with the problem you are trying to solve rather
than the solution you have in mind; the problem statement is the part most
likely to change the design.

### Improving documentation

Always welcome and always in scope. Documentation fixes are the best way to make
a first contribution — if something was confusing to you, it was confusing to
someone else, and you are the person best placed to fix it right now.

### Contributing code

Read the surrounding code first and match it. Consistency with what is already
there beats an individually better pattern applied in one place.

#### Go dependencies are vendored

After changing `go.mod` or `go.sum`, run `make tidy` (which runs `go mod
vendor`) and commit `go.mod`, `go.sum`, and the `vendor/` directory together. CI
fails if `vendor/` is out of sync.

## Pull request process

1. **Make `make qualify` pass.** Tests with the race detector, linting, and a
   vulnerability scan.
2. **Update documentation** if you changed behavior someone depends on.
3. **Sign off your commits** — see
   [Developer Certificate of Origin](#developer-certificate-of-origin).
4. **Open the pull request against `main`** with a clear summary. Reference
   related issues (`Fixes #123`).

Automated checks run on every pull request. If a check fails on your first
contribution and the failure looks unrelated to your change, say so in the pull
request rather than assuming it is your fault — it may well be ours.

Review covers correctness, test coverage, and consistency with existing
patterns. Address feedback by pushing new commits rather than force-pushing, so
the conversation stays readable; squashing happens at merge.

## Code style

- Wrap errors with context: `fmt.Errorf("context: %w", err)`, never a bare
  `return err`
- Log with `log/slog`, never `fmt.Println`
- Thread `context.Context` through every call that can block; never
  `context.Background()` outside `main` and tests
- Every outbound HTTP call uses a client with a timeout, never
  `http.DefaultClient`
- Parameterized SQL only — never build a query with `fmt.Sprintf` and user input
- Table-driven tests where there is more than one case

Commit messages follow [Conventional
Commits](https://www.conventionalcommits.org): `feat:`, `fix:`, `docs:`,
`refactor:`, `test:`, `chore:`. The subject line says what changed; the body
says why.

## Getting help

Open an [issue](https://github.com/thingzio/devradar/issues/new/choose) with the
question label. Search existing issues first.
