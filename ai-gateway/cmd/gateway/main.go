// Command gateway runs the AI security reverse proxy.
package main

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/sdballpark/ai-gateway/internal/audit"
	"github.com/sdballpark/ai-gateway/internal/config"
	"github.com/sdballpark/ai-gateway/internal/gateway"
	"github.com/sdballpark/ai-gateway/internal/ratelimit"
	"github.com/sdballpark/ai-gateway/internal/scanner"
	"github.com/sdballpark/ai-gateway/internal/secrets"
	"github.com/sdballpark/ai-gateway/internal/tenant"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("invalid UPSTREAM_URL: %v", err)
	}

	logger := audit.New()

	// pie is the shared detection engine. Ingress runs pie on the prompt; egress
	// runs the Go-native secret/PII detector AND pie (to catch reflected attacks)
	// on the response.
	pie := scanner.NewPIEScanner(cfg.PIEBinPath, cfg.ScanTimeout)
	egress := scanner.NewChain(scanner.NewEgressScanner(), pie)

	gw := &gateway.Gateway{
		Upstream:     upstream,
		Client:       &http.Client{Timeout: 30 * time.Second},
		Tenants:      tenant.NewRegistry(cfg.Tenants),
		Limiter:      ratelimit.New(),
		Vault:        secrets.NewVault(cfg.ProviderCreds),
		Ingress:      pie,
		Egress:       egress,
		Threshold:    cfg.Threshold,
		FailClosed:   cfg.FailClosed,
		MaxBodyBytes: cfg.MaxBodyBytes,
		Log:          logger,
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           gw,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Info("starting", "addr", cfg.Addr, "upstream", upstream.Redacted(),
		"fail_closed", cfg.FailClosed, "threshold", string(cfg.Threshold))
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
