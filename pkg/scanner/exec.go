package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// isInstalled reports whether bin is on PATH.
func isInstalled(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// runCmd runs cmd under ctx, killing the process if ctx is cancelled, then
// verifies outPath exists and contains parseable JSON. A scanner that dies on a
// malformed SBOM surfaces as a clean error rather than corrupt downstream data.
func runCmd(ctx context.Context, cmd *exec.Cmd, outPath string) error {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", cmd.Path, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done // reap
		return ctx.Err()
	case waitErr := <-done:
		info, statErr := os.Stat(outPath)
		if statErr != nil || info.Size() < 2 {
			return fmt.Errorf("%s produced no output (stderr=%s): %w",
				cmd.Path, truncate(stderr.String(), 500), waitErr)
		}
		if err := validateJSON(outPath); err != nil {
			return fmt.Errorf("%s output is not valid JSON: %w", cmd.Path, err)
		}
		return nil
	}
}

// captureVersion runs a version command and returns trimmed stdout, "" on error.
func captureVersion(bin string, args ...string) string {
	var out bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}

func validateJSON(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var raw json.RawMessage
	return json.NewDecoder(f).Decode(&raw)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
