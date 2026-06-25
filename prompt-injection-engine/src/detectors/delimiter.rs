//! Prompt-boundary breakout: injected role/system delimiters and fake
//! "end of prompt" markers that try to convince the model the trusted context
//! has ended. OWASP LLM01 / ATLAS AML.T0051.000.
//!
//! Note: unlike the other regex detectors this one does NOT collapse whitespace
//! in normalization-equivalent ways that would destroy delimiter structure — it
//! relies on signatures matching the literal token shapes (e.g. <|system|>), so
//! we lowercase only via the shared normalizer, which preserves the tokens.

use super::{match_signatures, normalize, Category, Detection, Detector};
use crate::signatures::Signature;

pub struct Delimiter {
    sigs: Vec<Signature>,
}

impl Delimiter {
    pub fn new(sigs: Vec<Signature>) -> Self {
        Self { sigs }
    }
}

impl Detector for Delimiter {
    fn name(&self) -> &'static str {
        "delimiter"
    }
    fn category(&self) -> Category {
        Category::Delimiter
    }
    fn scan(&self, input: &str) -> Vec<Detection> {
        let normalized = normalize(input);
        match_signatures(&normalized, &self.sigs, self.name(), false)
    }
}
