// Package config loads gateway settings from the environment. For a demo it
// registers a single tenant and provider credential from env; in production the
// tenant registry and vault would be backed by a secrets manager (e.g. Azure Key
// Vault) rather than environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/sdballpark/ai-gateway/internal/scanner"
	"github.com/sdballpark/ai-gateway/internal/tenant"
)

type Config struct {
	Addr         string
	UpstreamURL  string
	PIEBinPath   string
	ScanTimeout  time.Duration
	FailClosed   bool
	Threshold    scanner.Severity
	MaxBodyBytes int64

	Tenants       map[string]tenant.Tenant // gateway api key -> tenant
	ProviderCreds map[string]string        // provider -> upstream credential
}

func FromEnv() (Config, error) {
	c := Config{
		Addr:         getenv("GATEWAY_ADDR", ":8080"),
		UpstreamURL:  os.Getenv("UPSTREAM_URL"),
		PIEBinPath:   getenv("PIE_BIN", "pie"),
		ScanTimeout:  getdur("SCAN_TIMEOUT", 2*time.Second),
		FailClosed:   getbool("FAIL_CLOSED", true),
		Threshold:    scanner.Severity(getenv("BLOCK_THRESHOLD", "high")),
		MaxBodyBytes: getint64("MAX_BODY_BYTES", 1<<20), // 1 MiB
	}
	if c.UpstreamURL == "" {
		return c, fmt.Errorf("UPSTREAM_URL is required")
	}

	// Demo wiring: one tenant + one provider credential from env.
	tenantKey := getenv("DEMO_TENANT_KEY", "demo-tenant-key")
	provider := getenv("DEMO_PROVIDER", "openai")
	cred := os.Getenv("PROVIDER_CRED")
	if cred == "" {
		return c, fmt.Errorf("PROVIDER_CRED is required")
	}
	c.Tenants = map[string]tenant.Tenant{
		tenantKey: {ID: "demo", Provider: provider, RateRPS: getfloat("DEMO_RPS", 5), Burst: getfloat("DEMO_BURST", 10)},
	}
	c.ProviderCreds = map[string]string{provider: cred}
	return c, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getbool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func getint64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func getfloat(k string, def float64) float64 {
	if v := os.Getenv(k); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func getdur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
