//! Detector trait, shared types, and the matching primitive every detector uses.
//!
//! Design note: four of the five detectors (instruction-override, role-hijack,
//! delimiter, exfil-markers) are *signature-driven* — they differ only in which
//! category of signatures they own and how they normalize input before matching.
//! The fifth, `encoding`, is genuinely different: it decodes candidate payloads
//! and re-scans the plaintext through the other signatures. So the regex-driven
//! detectors share `match_signatures` here rather than duplicating match logic,
//! and `encoding` lives in its own module with distinct behavior.

pub mod delimiter;
pub mod encoding;
pub mod exfil_markers;
pub mod instruction_override;
pub mod role_hijack;

use serde::{Deserialize, Serialize};

use crate::signatures::Signature;

/// Ordered severity. Derives `Ord` so `verdict.max_severity()` and threshold
/// comparisons (`severity >= High`) are just comparisons — no lookup table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// The attack class a signature belongs to. Maps 1:1 to a detector and is used
/// to partition a loaded signature set across detectors at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    InstructionOverride,
    RoleHijack,
    Delimiter,
    Encoding,
    ExfilMarkers,
}

/// A single hit. Carries the taxonomy refs (OWASP/ATLAS) so downstream consumers
/// — the Go gateway, the TS firewall, a SIEM — get audit-ready output, not just
/// a boolean.
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub detector: &'static str,
    pub signature_id: String,
    pub category: Category,
    pub severity: Severity,
    /// A short window of text around the match, for triage. Never the full input.
    pub excerpt: String,
    pub owasp: Option<String>,
    pub atlas: Option<String>,
    /// True when this hit was found only after decoding an encoded payload — i.e.
    /// the attacker tried to smuggle it. That's a stronger signal of intent, so
    /// the encoding detector escalates severity when it sets this.
    pub via_encoding: bool,
}

/// Every detector implements this. Keeping it object-safe lets the scanner hold
/// `Vec<Box<dyn Detector>>` and lets a future detector be added without touching
/// the scanner — the extensibility story a lead would design for.
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn category(&self) -> Category;
    fn scan(&self, input: &str) -> Vec<Detection>;
}

/// Normalize input before matching to defeat trivial evasion:
///   - strip zero-width characters (U+200B–U+200D, U+FEFF) used to break up
///     keywords like "ig​nore" so a naive regex misses them;
///   - lowercase, so signatures can be written case-insensitively without every
///     pattern carrying `(?i)`;
///   - collapse runs of whitespace to a single space, defeating "i g n o r e"
///     and newline-spamming evasion.
///
/// Returns an owned String because every transform here can change length.
pub(crate) fn normalize(input: &str) -> String {
    let stripped: String = input
        .chars()
        .filter(|c| !matches!(*c, '\u{200B}'..='\u{200D}' | '\u{FEFF}'))
        .collect();
    let lowered = stripped.to_lowercase();
    // Collapse whitespace runs without allocating per-char.
    let mut out = String::with_capacity(lowered.len());
    let mut prev_ws = false;
    for c in lowered.chars() {
        if c.is_whitespace() {
            if !prev_ws {
                out.push(' ');
            }
            prev_ws = true;
        } else {
            out.push(c);
            prev_ws = false;
        }
    }
    out.trim().to_string()
}

/// Run a set of signatures against already-normalized text. Shared by all the
/// regex-driven detectors and reused by the encoding detector on decoded text.
///
/// `via_encoding` is threaded through so a hit found inside a decoded payload is
/// tagged (and later severity-escalated) as a smuggling attempt.
pub(crate) fn match_signatures(
    text: &str,
    sigs: &[Signature],
    detector: &'static str,
    via_encoding: bool,
) -> Vec<Detection> {
    let mut out = Vec::new();
    for sig in sigs {
        if let Some(m) = sig.regex.find(text) {
            let severity = if via_encoding {
                escalate(sig.severity)
            } else {
                sig.severity
            };
            out.push(Detection {
                detector,
                signature_id: sig.id.clone(),
                category: sig.category,
                severity,
                excerpt: excerpt(text, m.start(), m.end()),
                owasp: sig.owasp.clone(),
                atlas: sig.atlas.clone(),
                via_encoding,
            });
        }
    }
    out
}

/// A smuggled payload is a stronger intent signal than the same text in the
/// clear, so bump one severity level (capped at Critical).
pub(crate) fn escalate(s: Severity) -> Severity {
    match s {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High => Severity::Critical,
        Severity::Critical => Severity::Critical,
    }
}

/// Extract a bounded, char-safe window around a match for triage output.
/// Works on char boundaries so we never panic slicing a multi-byte input.
fn excerpt(text: &str, start: usize, end: usize) -> String {
    const PAD: usize = 24;
    let lo = text[..start]
        .char_indices()
        .rev()
        .nth(PAD)
        .map(|(i, _)| i)
        .unwrap_or(0);
    let hi = text[end..]
        .char_indices()
        .nth(PAD)
        .map(|(i, _)| end + i)
        .unwrap_or(text.len());
    let mut s = String::new();
    if lo > 0 {
        s.push('…');
    }
    s.push_str(&text[lo..hi]);
    if hi < text.len() {
        s.push('…');
    }
    s
}
