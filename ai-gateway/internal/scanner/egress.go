package scanner

import (
	"context"
	"regexp"
	"strconv"
)

// EgressScanner detects concrete secret/PII leakage in MODEL OUTPUT — the egress
// channel the gateway uniquely controls. It complements (does not duplicate) the
// pie engine: pie catches injection/exfil *phrasing*; this catches the *payload*
// actually leaking out (a provider key, AWS key, private key, SSN, card number).
//
// Critically, every Excerpt is REDACTED before it leaves this scanner, so a leaked
// secret never lands in the gateway's own audit log — a scanner that logged the
// secret it caught would be its own exfil vector.
type EgressScanner struct {
	rules []egressRule
}

type egressRule struct {
	name     string
	re       *regexp.Regexp
	severity Severity
	owasp    string
	luhn     bool // validate digit runs with the Luhn checksum before flagging
}

func NewEgressScanner() *EgressScanner {
	return &EgressScanner{rules: []egressRule{
		{"openai_api_key", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), Critical, "LLM02", false},
		{"aws_access_key_id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Critical, "LLM02", false},
		{"private_key_block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), Critical, "LLM02", false},
		{"bearer_token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}`), High, "LLM02", false},
		{"us_ssn", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), High, "LLM02", false},
		// Card matcher is intentionally broad, then Luhn-filtered to cut the false
		// positives a bare 13–19 digit regex would produce on order numbers etc.
		{"credit_card", regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), High, "LLM02", true},
	}}
}

func (e *EgressScanner) Name() string { return "egress" }

func (e *EgressScanner) Scan(_ context.Context, text string) ([]Detection, error) {
	var out []Detection
	for _, r := range e.rules {
		for _, m := range r.re.FindAllString(text, -1) {
			if r.luhn && !luhnValid(m) {
				continue
			}
			out = append(out, Detection{
				Source:   "egress",
				Detector: r.name,
				Severity: r.severity,
				Excerpt:  redactMatch(m), // never the raw secret
				OWASP:    r.owasp,
			})
		}
	}
	return out, nil
}

// redactMatch keeps a short non-sensitive prefix for triage and masks the rest,
// so the value is recognizable in a log without being recoverable from it.
func redactMatch(s string) string {
	const keep = 3
	if len(s) <= keep {
		return "[redacted]"
	}
	return s[:keep] + "…[redacted " + strconv.Itoa(len(s)-keep) + " chars]"
}

// luhnValid runs the Luhn checksum over the digits in s.
func luhnValid(s string) bool {
	digits := make([]int, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
