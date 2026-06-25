//! Output-side data-leakage phrasing: attempts to coax the model into revealing
//! its system prompt, its context, or sensitive records it can see.
//! OWASP LLM02 (Sensitive Information Disclosure) / ATLAS AML.T0057.

use super::{match_signatures, normalize, Category, Detection, Detector};
use crate::signatures::Signature;

pub struct ExfilMarkers {
    sigs: Vec<Signature>,
}

impl ExfilMarkers {
    pub fn new(sigs: Vec<Signature>) -> Self {
        Self { sigs }
    }
}

impl Detector for ExfilMarkers {
    fn name(&self) -> &'static str {
        "exfil_markers"
    }
    fn category(&self) -> Category {
        Category::ExfilMarkers
    }
    fn scan(&self, input: &str) -> Vec<Detection> {
        let normalized = normalize(input);
        match_signatures(&normalized, &self.sigs, self.name(), false)
    }
}
