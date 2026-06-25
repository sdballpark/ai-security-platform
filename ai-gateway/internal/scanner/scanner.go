// Package scanner defines the detection contract the gateway uses on both the
// ingress (user prompt) and egress (model response) paths.
//
// Division of labor across the platform:
//   - the Rust `pie` engine owns injection/jailbreak/exfil *language* patterns
//     and is invoked via PIEScanner — one detection brain, shared by the gateway
//     and the MCP firewall rather than reimplemented per language;
//   - EgressScanner owns *egress concretes* the gateway is uniquely positioned
//     to see: a provider key, AWS key, private-key block, SSN, or card number
//     appearing in the model's OUTPUT. That is leakage detection, not language
//     detection, so it lives here in Go and runs only on responses.
package scanner

import (
	"context"
	"fmt"
)

// Severity is ordered; compare with Rank/AtLeast rather than string equality.
type Severity string

const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

func (s Severity) Rank() int {
	switch s {
	case Info:
		return 1
	case Low:
		return 2
	case Medium:
		return 3
	case High:
		return 4
	case Critical:
		return 5
	default:
		return 0
	}
}

// AtLeast reports whether s meets or exceeds threshold t.
func (s Severity) AtLeast(t Severity) bool { return s.Rank() >= t.Rank() }

// Detection is one finding. Excerpt is always safe to log: scanners that match
// secrets MUST redact the value before populating it (see EgressScanner).
type Detection struct {
	Source      string   `json:"source"` // "pie" or "egress"
	Detector    string   `json:"detector"`
	SignatureID string   `json:"signature_id,omitempty"`
	Category    string   `json:"category,omitempty"`
	Severity    Severity `json:"severity"`
	Excerpt     string   `json:"excerpt,omitempty"`
	OWASP       string   `json:"owasp,omitempty"`
	ATLAS       string   `json:"atlas,omitempty"`
	ViaEncoding bool     `json:"via_encoding,omitempty"`
}

// Scanner inspects text and returns findings. An error means the scan did not
// complete — the caller decides fail-open vs fail-closed; the scanner does not.
type Scanner interface {
	Scan(ctx context.Context, text string) ([]Detection, error)
	Name() string
}

// Chain runs scanners in order and concatenates findings. The first error
// aborts and is returned with whatever was gathered, so the gateway can apply
// its fail-closed policy.
type Chain struct {
	scanners []Scanner
}

func NewChain(s ...Scanner) *Chain { return &Chain{scanners: s} }

func (c *Chain) Name() string { return "chain" }

func (c *Chain) Scan(ctx context.Context, text string) ([]Detection, error) {
	var out []Detection
	for _, s := range c.scanners {
		ds, err := s.Scan(ctx, text)
		out = append(out, ds...)
		if err != nil {
			return out, fmt.Errorf("scanner %q: %w", s.Name(), err)
		}
	}
	return out, nil
}

// MaxSeverity returns the highest severity present, or "" for an empty set.
func MaxSeverity(ds []Detection) Severity {
	var max Severity
	for _, d := range ds {
		if d.Severity.Rank() > max.Rank() {
			max = d.Severity
		}
	}
	return max
}
