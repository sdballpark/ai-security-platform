# AI Security Platform

Defense-in-depth for LLM applications, built as three control points of a single
stack. Each component is written in the language its layer's real-world tooling
uses, and they share one detection engine rather than reimplementing detection
three times.

```
                         ┌───────────────────────────────────────────┐
                         │          prompt-injection-engine            │
                         │              (Rust — the core)              │
                         │   signature-driven scan → severity verdict  │
                         └──────────────▲───────────────▲──────────────┘
                          input scan    │               │   output scan
              ┌──────────────────────┐  │               │  ┌──────────────────────┐
              │   mcp-tool-firewall   │──┘               └──│      ai-gateway       │
              │     (TypeScript)      │                     │        (Go)           │
              │  validate tool I/O,   │                     │  exfil + abuse        │
              │  least privilege,     │                     │  controls in front of │
              │  blast-radius gate    │                     │  model providers      │
              └──────────────────────┘                     └──────────────────────┘
```

## Components

| Component | Language | Role | Status |
|---|---|---|---|
| [`prompt-injection-engine`](./prompt-injection-engine) | Rust | Detection core: prompt-injection, jailbreak, and exfil pattern detection, with decode-and-rescan for encoded payloads and a CI-gated adversarial corpus. | ✅ built |
| [`ai-gateway`](./ai-gateway) | Go | Security reverse proxy: per-tenant isolation, credential custody, and bidirectional scanning (consumes the engine on ingress; egress secret/PII detection). | ✅ built |
| `mcp-tool-firewall` | TypeScript | MCP tool-call firewall: schema validation, least-privilege allow-lists, output validation, and escalating blast-radius containment. | 🚧 planned |

The enforcement layers (Go gateway, TS firewall) call into the Rust engine rather
than duplicating its logic. The engine owns injection/exfil **language** patterns;
each enforcement layer adds the **concrete** controls only it can see — the gateway
catches secrets/PII leaking in model output; the firewall gates tool invocations.

## Coverage

Findings are mapped to recognized taxonomies so the work speaks the language a
security review and an audit already use.

| Risk | OWASP LLM Top 10 (2025) | MITRE ATLAS (v5.4.0) | Where enforced |
|---|---|---|---|
| Prompt injection / jailbreak | LLM01 | `AML.T0051`, `AML.T0054` | engine; gateway ingress; firewall |
| Sensitive information disclosure | LLM02 | `AML.T0057` | engine; gateway egress |
| Insecure tool / function-call use | LLM06 (excessive agency) | `AML.T0051.000` | firewall (planned) |

## Build & test

Each component builds and tests independently:

```bash
# Rust detection engine
cd prompt-injection-engine && cargo test --all

# Go security gateway (consumes the engine binary via PIE_BIN)
cd ai-gateway && go test -race ./...
```

CI runs per-subtree via path-filtered workflows in `.github/workflows/`, so a
change to one component only triggers that component's pipeline.


## Author

**Robert Bogan**

AI Security & Governance Engineer | CISSP, CISM, CRISC

[LinkedIn](https://www.linkedin.com/in/robert-l-bogan-jr)

## License

MIT — original work. No proprietary logic from any prior employer.
