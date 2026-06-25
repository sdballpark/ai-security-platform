package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// PIEScanner shells out to the Rust `pie` binary (prompt-injection-engine),
// feeding text on stdin and parsing its JSON verdict. This is the cross-repo
// integration point: the gateway does not reimplement injection detection, it
// calls the shared engine.
//
// Process-per-scan is acceptable on the ingress path (one scan per request) but
// for very high throughput the right evolution is a `pie serve` sidecar over a
// unix socket. That tradeoff is named here rather than hidden.
type PIEScanner struct {
	BinPath string
	Timeout time.Duration
}

func NewPIEScanner(binPath string, timeout time.Duration) *PIEScanner {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &PIEScanner{BinPath: binPath, Timeout: timeout}
}

func (p *PIEScanner) Name() string { return "pie" }

// Mirrors the JSON emitted by `pie scan --format json`.
type pieOutput struct {
	Blocked    bool           `json:"blocked"`
	Clean      bool           `json:"clean"`
	Detections []pieDetection `json:"detections"`
}

type pieDetection struct {
	Detector    string   `json:"detector"`
	SignatureID string   `json:"signature_id"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Excerpt     string   `json:"excerpt"`
	OWASP       string   `json:"owasp"`
	ATLAS       string   `json:"atlas"`
	ViaEncoding bool     `json:"via_encoding"`
}

func (p *PIEScanner) Scan(ctx context.Context, text string) ([]Detection, error) {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	// --threshold critical keeps pie's own exit code quiet; we make the block
	// decision at the gateway from the returned detections, not pie's exit code.
	cmd := exec.CommandContext(ctx, p.BinPath, "scan", "--format", "json", "--threshold", "critical", "-")
	cmd.Stdin = strings.NewReader(text)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// pie exit codes: 0 clean, 1 blocked (stdout still valid JSON), >=2 error.
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if exit.ExitCode() >= 2 {
				return nil, fmt.Errorf("pie error (exit %d): %s", exit.ExitCode(), strings.TrimSpace(stderr.String()))
			}
			// exit 1: a detection met pie's threshold — not an error, parse stdout.
		} else {
			return nil, fmt.Errorf("invoking pie: %w", err)
		}
	}

	var out pieOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("parsing pie output: %w", err)
	}

	ds := make([]Detection, 0, len(out.Detections))
	for _, d := range out.Detections {
		ds = append(ds, Detection{
			Source:      "pie",
			Detector:    d.Detector,
			SignatureID: d.SignatureID,
			Category:    d.Category,
			Severity:    d.Severity,
			Excerpt:     d.Excerpt,
			OWASP:       d.OWASP,
			ATLAS:       d.ATLAS,
			ViaEncoding: d.ViaEncoding,
		})
	}
	return ds, nil
}
