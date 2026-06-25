//! Signature loading.
//!
//! ── Why signatures are TOML loaded at runtime, not hardcoded in Rust ──────────
//!
//! Signatures are DATA, not LOGIC. New injection phrasings appear constantly; a
//! security engineer must be able to add one and ship a new pack WITHOUT
//! recompiling or redeploying the engine. Hardcoding signatures would chain the
//! threat-intel update cadence to the software-release cadence — the wrong
//! coupling for a detection control.
//!
//! Why TOML specifically:
//!   * over YAML — no significant-whitespace footguns and no type-coercion
//!     surprises (the "Norway problem" where `no` parses as boolean false,
//!     `yes`→true, bare numbers reinterpreted). For a SECURITY tool, a config
//!     format with fewer parsing ambiguities is the safer default.
//!   * over JSON — comments. Each signature carries an inline `rationale` field
//!     AND can carry `#` comments, so a pack documents the threat it addresses.
//!   * auditability — a TOML pack diffs cleanly in a pull request, so tuning a
//!     signature is a reviewable change with a paper trail: the governance
//!     evidence security work is expected to produce.
//!
//! The default pack is embedded with `include_str!` so the library works with
//! zero filesystem dependencies; additional packs layer on from disk.

use regex::Regex;
use serde::Deserialize;

use crate::detectors::{Category, Severity};
use crate::EngineError;

/// The embedded default pack — ships in the binary, no file needed at runtime.
const DEFAULT_PACK: &str = include_str!("../signatures/default.toml");

/// As authored in TOML (pattern is still a string here).
#[derive(Debug, Deserialize)]
struct RawSignature {
    id: String,
    category: Category,
    pattern: String,
    severity: Severity,
    #[allow(dead_code)] // captured for documentation/audit; not used at match time
    rationale: String,
    #[serde(default)]
    owasp: Option<String>,
    #[serde(default)]
    atlas: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignatureFile {
    #[serde(default)]
    signature: Vec<RawSignature>,
}

/// A compiled signature: pattern is now a `Regex`, ready to match.
#[derive(Debug, Clone)]
pub struct Signature {
    pub id: String,
    pub category: Category,
    pub regex: Regex,
    pub severity: Severity,
    pub owasp: Option<String>,
    pub atlas: Option<String>,
}

/// A loaded, compiled set of signatures.
#[derive(Debug, Clone, Default)]
pub struct SignatureSet {
    pub signatures: Vec<Signature>,
}

impl SignatureSet {
    /// Load and compile the embedded default pack.
    pub fn default_pack() -> Result<Self, EngineError> {
        Self::from_toml_str(DEFAULT_PACK)
    }

    /// Parse and compile signatures from a TOML string. Compiles every regex up
    /// front so a malformed pattern fails loudly at load time, never silently at
    /// match time — and so an invalid pack can't be half-applied.
    pub fn from_toml_str(s: &str) -> Result<Self, EngineError> {
        let file: SignatureFile =
            toml::from_str(s).map_err(|e| EngineError::Parse(e.to_string()))?;
        let mut signatures = Vec::with_capacity(file.signature.len());
        for raw in file.signature {
            let regex = Regex::new(&raw.pattern)
                .map_err(|e| EngineError::BadPattern(raw.id.clone(), e.to_string()))?;
            signatures.push(Signature {
                id: raw.id,
                category: raw.category,
                regex,
                severity: raw.severity,
                owasp: raw.owasp,
                atlas: raw.atlas,
            });
        }
        Ok(Self { signatures })
    }

    /// Load and compile a pack from disk.
    pub fn from_path(path: impl AsRef<std::path::Path>) -> Result<Self, EngineError> {
        let s = std::fs::read_to_string(path.as_ref())
            .map_err(|e| EngineError::Io(path.as_ref().display().to_string(), e.to_string()))?;
        Self::from_toml_str(&s)
    }

    /// Merge another pack on top of this one (used for `--signatures a --signatures b`).
    pub fn extend(&mut self, other: SignatureSet) {
        self.signatures.extend(other.signatures);
    }

    /// All signatures in a category — used to partition the set across detectors.
    pub fn in_category(&self, cat: Category) -> Vec<Signature> {
        self.signatures
            .iter()
            .filter(|s| s.category == cat)
            .cloned()
            .collect()
    }

    /// All signatures NOT in the encoding category — what the encoding detector
    /// re-scans decoded plaintext against.
    pub fn non_encoding(&self) -> Vec<Signature> {
        self.signatures
            .iter()
            .filter(|s| s.category != Category::Encoding)
            .cloned()
            .collect()
    }
}
