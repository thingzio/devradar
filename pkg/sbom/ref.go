package sbom

import "strings"

// SplitRef decomposes an image reference into its repository, tag, and digest.
// Any of tag/digest may be empty. The repository is the registry/path with no
// tag or digest — the stable identity DevRadar groups an image's SBOMs by
// (across versions and digests).
//
//	quay.io/jetstack/cainjector:v1.20.2@sha256:ab…  -> repo=quay.io/jetstack/cainjector tag=v1.20.2 digest=sha256:ab…
//	quay.io/jetstack/cainjector@sha256:ab…          -> repo=quay.io/jetstack/cainjector tag=""      digest=sha256:ab…
//	registry:5000/app:1.2                            -> repo=registry:5000/app           tag=1.2     digest=""
//	alpine                                           -> repo=alpine                       tag=""      digest=""
func SplitRef(ref string) (repository, tag, digest string) {
	// Digest first: everything after '@' (if it's a real sha256:… digest).
	if base, dig, found := strings.Cut(ref, "@"); found {
		if d := asDigest(dig); d != "" {
			ref, digest = base, d
		}
	}
	// Tag: text after the last ':' that contains no '/' (a port is host:port/…,
	// so its colon is always followed by a slash before the tag).
	if i := strings.LastIndex(ref, ":"); i != -1 && !strings.Contains(ref[i+1:], "/") {
		repository, tag = ref[:i], ref[i+1:]
	} else {
		repository = ref
	}
	return repository, tag, digest
}

// Repository returns just the repository component of an image reference — the
// grouping key for an image across its versions and digests.
func Repository(ref string) string {
	repo, _, _ := SplitRef(ref)
	return repo
}
