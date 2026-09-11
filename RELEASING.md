# Releasing

Releases are cut by pushing a semver tag. Everything after that is automated.

This document is for maintainers. Contributors do not need it — see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Cutting a release

```shell
make bump-patch   # v1.2.3 -> v1.2.4
make bump-minor   # v1.2.3 -> v1.3.0
make bump-major   # v1.2.3 -> v2.0.0
```

Each target runs `tools/bump`, which:

1. Refuses to run if the working tree is dirty.
2. Refuses to run if there are unpushed commits.
3. Reads the current version from `git describe --tags --abbrev=0`.
4. Computes the next version, creates the tag, and pushes it.

Pushing the tag is what triggers the release. There is no separate "publish"
step and no manual step in the GitHub UI.

Both guards matter. A tag pointing at a commit that is not on `origin/main`
produces a release nobody can reproduce from the public history.

## What happens on the tag

`.github/workflows/release.yaml` runs on any tag matching
``v*.*.*``:

1. **Tests run first.** The same reusable workflow that gates pull requests. A
   failing test aborts the release before anything is published.
2. **Build and publish.** goreleaser builds the `devradar-serve`, `devradar-scan`, and `devradar-deliver` binaries, a ko-built service image, and a Docker-built scan image and pushes the
   container images to Artifact Registry. Authentication to Google Cloud is
   keyless via Workload Identity Federation — there are no long-lived cloud
   credentials in this repository.
3. **Release notes.** A GitHub release is created for the tag.
4. **Deploy.** A separate job resolves an immutable deployment bundle and updates the reference Cloud Run instance.

## Versioning

[Semantic versioning](https://semver.org), with the caveat that this project is
pre-1.0 (`v0.14.0` at the time of writing). Until 1.0, minor versions may
carry breaking changes; patch versions do not.

When 1.0 arrives, this section gets rewritten with a real compatibility
commitment. Until then, pin exactly if you depend on this.

## If a release goes wrong

**The tag exists but the workflow failed.** Fix the problem on `main`, then cut
a new patch version. Do not delete and re-push the tag — someone may already
have consumed it, and a moving tag is worse than a skipped version number.
Version numbers are free.

**A released version has a serious defect.** Cut a new patch release. There is
no yank mechanism, and the supported-version policy in
[SECURITY.md](SECURITY.md) means only the latest release is maintained anyway.

## Release checklist

Nothing here is enforced by tooling, which is why it is written down:

- [ ] `make qualify` passes on the commit being tagged
- [ ] `main` is pushed and CI is green on it
- [ ] Anything user-visible is reflected in the docs
- [ ] If a migration is included, it is numbered above the production
      high-water mark — see [DEVELOPMENT.md](DEVELOPMENT.md)
