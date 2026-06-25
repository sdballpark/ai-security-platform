// Package gateway is the security reverse proxy: it authenticates the tenant,
// enforces per-tenant rate limits, scans the inbound prompt, injects the upstream
// provider credential, scans the model's response for leakage, and only then
// relays it — auditing every decision.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sdballpark/ai-gateway/internal/ratelimit"
	"github.com/sdballpark/ai-gateway/internal/scanner"
	"github.com/sdballpark/ai-gateway/internal/secrets"
	"github.com/sdballpark/ai-gateway/internal/tenant"
)

type Gateway struct {
	Upstream     *url.URL
	Client       *http.Client
	Tenants      *tenant.Registry
	Limiter      *ratelimit.Limiter
	Vault        *secrets.Vault
	Ingress      scanner.Scanner  // runs on the user prompt (pie)
	Egress       scanner.Scanner  // runs on the model response (egress + pie)
	Threshold    scanner.Severity // block if any detection >= this
	FailClosed   bool             // on scanner error: block (true) or pass (false)
	MaxBodyBytes int64            // cap on request/response bytes buffered
	Log          *slog.Logger
}

// hopByHop headers must not be forwarded between client and upstream.
var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"Transfer-Encoding": true, "Te": true, "Trailer": true, "Upgrade": true,
	// Authorization and the gateway API key are stripped explicitly below.
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	// 1. Authenticate the tenant from the gateway-issued key.
	apiKey := r.Header.Get("X-API-Key")
	t, ok := g.Tenants.Resolve(apiKey)
	if !ok {
		g.deny(w, r, http.StatusUnauthorized, "unauthorized", "unknown_api_key", start, nil)
		return
	}

	// 2. Per-tenant rate limit (tenant isolation).
	if !g.Limiter.Allow(t.ID, t.RateRPS, t.Burst) {
		g.deny(w, r, http.StatusTooManyRequests, "rate limit exceeded", "rate_limited", start, &t)
		return
	}

	// 3. Read the request body under a hard cap.
	body, err := io.ReadAll(io.LimitReader(r.Body, g.MaxBodyBytes))
	if err != nil {
		g.deny(w, r, http.StatusBadRequest, "cannot read request body", "body_read_error", start, &t)
		return
	}

	// 4. Ingress scan: block obvious injection before it ever reaches the model.
	if block, ds := g.evaluate(ctx, g.Ingress, string(body), "ingress"); block {
		g.blocked(w, r, http.StatusForbidden, "ingress", ds, start, &t)
		return
	}

	// 5. Build the upstream request: strip client auth, inject the provider
	//    credential. The client's gateway key is never forwarded upstream.
	cred, ok := g.Vault.Credential(t.Provider)
	if !ok {
		// Misconfiguration — never fall back to sending the request unauthenticated.
		g.deny(w, r, http.StatusInternalServerError, "provider unavailable", "missing_provider_credential", start, &t)
		return
	}
	upReq, err := g.buildUpstream(ctx, r, body, cred)
	if err != nil {
		g.deny(w, r, http.StatusBadGateway, "cannot build upstream request", "upstream_build_error", start, &t)
		return
	}

	// 6. Call the model provider.
	resp, err := g.Client.Do(upReq)
	if err != nil {
		g.deny(w, r, http.StatusBadGateway, "upstream request failed", "upstream_error", start, &t)
		return
	}
	defer resp.Body.Close()

	// 7. Buffer the response. Scanning for exfil requires the whole body; a token
	//    stream can't be reliably scanned without a sliding-window buffer anyway,
	//    so we buffer and accept the loss of streaming on this control path.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, g.MaxBodyBytes))
	if err != nil {
		g.deny(w, r, http.StatusBadGateway, "cannot read upstream response", "upstream_read_error", start, &t)
		return
	}

	// 8. Egress scan: catch secret/PII leakage or reflected injection in output.
	if block, ds := g.evaluate(ctx, g.Egress, string(respBody), "egress"); block {
		// Return a sanitized error — NEVER the leaking content.
		g.blocked(w, r, http.StatusBadGateway, "egress", ds, start, &t)
		return
	}

	// 9. Relay the clean response to the client.
	for k, vals := range resp.Header {
		if hopByHop[k] {
			continue
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	g.Log.Info("allowed",
		"tenant", t.ID, "status", resp.StatusCode,
		"req_bytes", len(body), "resp_bytes", len(respBody),
		"latency_ms", time.Since(start).Milliseconds(),
	)
}

func (g *Gateway) buildUpstream(ctx context.Context, r *http.Request, body []byte, cred string) (*http.Request, error) {
	target := *g.Upstream
	target.Path = singleJoin(g.Upstream.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	// Copy client headers except hop-by-hop and anything auth-bearing.
	for k, vals := range r.Header {
		if hopByHop[k] || k == "Authorization" || k == "X-Api-Key" {
			continue
		}
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	// Inject the upstream credential. The client never saw and never sent this.
	req.Header.Set("Authorization", "Bearer "+cred)
	return req, nil
}

// evaluate runs a scanner and applies the block decision plus fail-closed policy.
func (g *Gateway) evaluate(ctx context.Context, s scanner.Scanner, text, direction string) (bool, []scanner.Detection) {
	ds, err := s.Scan(ctx, text)
	if err != nil {
		g.Log.Error("scan_error", "direction", direction, "scanner", s.Name(), "err", err.Error())
		return g.FailClosed, ds // fail-closed → treat scan failure as a block
	}
	return scanner.MaxSeverity(ds).AtLeast(g.Threshold), ds
}

// deny writes a clean JSON error and audits it. No secrets, no leaking content.
func (g *Gateway) deny(w http.ResponseWriter, r *http.Request, status int, msg, reason string, start time.Time, t *tenant.Tenant) {
	tenantID := "-"
	if t != nil {
		tenantID = t.ID
	}
	g.Log.Warn("denied",
		"tenant", tenantID, "status", status, "reason", reason,
		"path", r.URL.Path, "latency_ms", time.Since(start).Milliseconds(),
	)
	writeJSON(w, status, map[string]any{"error": msg, "reason": reason})
}

// blocked audits a scan block with the (already-redacted) detections and returns
// a sanitized response carrying only the finding metadata, never the payload.
func (g *Gateway) blocked(w http.ResponseWriter, r *http.Request, status int, direction string, ds []scanner.Detection, start time.Time, t *tenant.Tenant) {
	tenantID := "-"
	if t != nil {
		tenantID = t.ID
	}
	g.Log.Warn("blocked",
		"tenant", tenantID, "direction", direction, "status", status,
		"max_severity", string(scanner.MaxSeverity(ds)), "detections", len(ds),
		"path", r.URL.Path, "latency_ms", time.Since(start).Milliseconds(),
	)
	// Surface finding metadata (detector/category/severity), which is safe — the
	// excerpts were redacted at the scanner — but not the original content.
	findings := make([]map[string]any, 0, len(ds))
	for _, d := range ds {
		findings = append(findings, map[string]any{
			"source": d.Source, "detector": d.Detector, "category": d.Category,
			"severity": string(d.Severity), "owasp": d.OWASP, "atlas": d.ATLAS,
		})
	}
	writeJSON(w, status, map[string]any{
		"error":     "request blocked by AI security policy",
		"direction": direction,
		"findings":  findings,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func singleJoin(a, b string) string {
	switch {
	case strings.HasSuffix(a, "/") && strings.HasPrefix(b, "/"):
		return a + b[1:]
	case !strings.HasSuffix(a, "/") && !strings.HasPrefix(b, "/") && a != "":
		return a + "/" + b
	default:
		return a + b
	}
}
