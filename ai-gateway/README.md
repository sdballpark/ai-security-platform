# ai-gateway

A security reverse proxy in front of LLM providers. It authenticates the tenant,
enforces per-tenant rate limits, scans the inbound prompt and the model's
response, injects the upstream provider credential, and audits every decision.

This is the **enforcement layer** of a three-part AI-security stack. It does not
reimplement detection — it consumes the Rust [`prompt-injection-engine`](../prompt-injection-engine)
(`pie`) as the shared detection brain, and adds the egress controls a gateway is
uniquely positioned to enforce.

```
        client ──X-API-Key──▶  ai-gateway (this repo, Go)
                               │  1. authenticate tenant
                               │  2. per-tenant rate limit (isolation)
                               │  3. INGRESS scan ──▶ pie (Rust engine)
                               │  4. inject provider credential
                               ▼
                          model provider
                               │
                               │  5. buffer response
                               │  6. EGRESS scan ──▶ egress (Go) + pie
                               ▼
                         clean response ──▶ client      (else: blocked, sanitized)
```

## Division of labor (why this isn't redundant with pie)

| Concern | Owner | Where |
|---|---|---|
| Injection / jailbreak / exfil **language** | `pie` (Rust) | ingress + egress |
| Leaked **secrets / PII** in model output | `EgressScanner` (Go) | egress only |
| Tenant auth, isolation, rate limiting | gateway | every request |
| Provider credential custody | gateway vault | upstream call |

`pie` detects the *phrasing* of an attack; the gateway's egress scanner detects
the *payload* actually leaking out (a provider key, AWS key, private-key block,
SSN, or Luhn-valid card number). One brain, shared across the platform, plus the
egress concretes only the gateway can see.

## What it defends (threat model)

- **Prompt injection on ingress** — blocked before the prompt reaches the model.
- **Data exfiltration on egress** — secrets and PII in the response are caught and
  the response is replaced with a sanitized error; the payload never reaches the
  client, and the redacted finding never carries the raw secret into the audit log.
- **Tenant isolation** — per-tenant token buckets; one tenant cannot exhaust
  another's quota. Each tenant's traffic uses its own upstream credential.
- **Credential custody** — clients hold a gateway-issued key, never a provider
  key. The gateway injects the real credential and never logs or returns it.

OWASP LLM01 (Prompt Injection) and LLM02 (Sensitive Information Disclosure);
MITRE ATLAS AML.T0051 / AML.T0054 (via `pie`) and AML.T0057 (egress leakage).

## Design decisions worth knowing

- **Fail-closed.** If a scanner errors or `pie` is unavailable, the request is
  **blocked**, not passed. An exfil control that fails open is not a control.
  Configurable via `FAIL_CLOSED`.
- **Buffered, not streamed.** Exfil scanning needs the whole response; a token
  stream can't be reliably scanned without a sliding-window buffer. The control
  path buffers and accepts the loss of streaming, by design.
- **Stdlib only.** No external dependencies — minimal supply-chain surface, audits
  cleanly, builds anywhere.
- **pie via subprocess.** The gateway invokes the `pie` binary per ingress scan.
  Fine at one-scan-per-request; the documented evolution for high throughput is a
  `pie serve` sidecar over a unix socket.

## Run it

```bash
go build -o gateway ./cmd/gateway

UPSTREAM_URL=https://api.your-provider.example \
PIE_BIN=/path/to/pie \
PROVIDER_CRED=sk-your-real-upstream-key \
DEMO_TENANT_KEY=demo-tenant-key \
BLOCK_THRESHOLD=high \
FAIL_CLOSED=true \
./gateway

# client uses the gateway key, never the provider key:
curl -XPOST -H "X-API-Key: demo-tenant-key" \
  --data 'summarize the earnings report' \
  http://localhost:8080/v1/chat
```

## Tests

```bash
go test -race ./...
```

- `internal/gateway` — full-path integration: 401 on bad key, credential
  injection, ingress block before upstream, egress secret-leak block (secret not
  returned to client), fail-closed on scanner error, 429 on rate limit.
- `internal/scanner` — egress secret/PII detection, redaction (no raw secret in
  the excerpt), Luhn filtering of non-card digit runs.
- `internal/ratelimit` — burst/refill behavior and tenant isolation.

## License

MIT — original work. No proprietary logic from any prior employer.
