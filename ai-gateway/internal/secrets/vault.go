// Package secrets holds upstream provider credentials and keeps them out of logs
// and out of client-visible surfaces. Credentials are injected into the upstream
// request by the gateway; they never originate from, or return to, the client.
package secrets

import (
	"regexp"
	"sync"
)

type Vault struct {
	mu    sync.RWMutex
	creds map[string]string // provider -> credential
}

func NewVault(creds map[string]string) *Vault {
	c := make(map[string]string, len(creds))
	for k, v := range creds {
		c[k] = v
	}
	return &Vault{creds: c}
}

// Credential returns the upstream secret for a provider. The bool is false if the
// provider is unknown, which the gateway treats as a configuration error (500),
// never as "send the request without auth".
func (v *Vault) Credential(provider string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	c, ok := v.creds[provider]
	return c, ok
}

// Redactors strip known secret shapes from any string about to be logged.
var redactors = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)(authorization|bearer)[:=]?\s*\S+`),
}

// Redact scrubs secrets from a string before it reaches a log sink.
func Redact(s string) string {
	for _, re := range redactors {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
