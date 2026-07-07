package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// isInstalled reports whether bin is on PATH.
func isInstalled(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// maxStderrBytes caps how much of a scanner's stderr we retain. The SBOM is
// attacker-controllable, so an induced stderr flood must not be an unbounded
// allocation; we only ever surface a truncated prefix for diagnostics anyway.
const maxStderrBytes = 64 << 10

// runCmd runs cmd under ctx, killing the process if ctx is cancelled, then
// verifies outPath exists and contains parseable JSON. A scanner that dies on a
// malformed SBOM surfaces as a clean error rather than corrupt downstream data.
func runCmd(ctx context.Context, cmd *exec.Cmd, outPath string) error {
	stderr := &cappedBuffer{limit: maxStderrBytes}
	cmd.Stderr = stderr

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

// versionProbeTimeout bounds the quick version/DB-status probes so a wedged
// binary can't hang job startup indefinitely.
const versionProbeTimeout = 30 * time.Second

// captureVersion runs a version command and returns trimmed stdout, "" on error.
// It is bounded by versionProbeTimeout so a hung probe can't stall the job.
func captureVersion(bin string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
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

// cappedBuffer is an io.Writer that retains at most limit bytes and silently
// drops the rest — bounding memory when capturing a subprocess's stderr driven
// by attacker-controllable SBOM input.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil // report full length so the process never blocks on a full pipe
}

func (c *cappedBuffer) String() string { return c.buf.String() }
