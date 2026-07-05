package converter

// DefaultRegistry returns a registry with the v1 converters registered: grype
// and trivy. Additional scanners register here without touching callers.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewGrype())
	r.Register(NewTrivy())
	return r
}
