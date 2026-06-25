//! Direct prompt-injection: text that tries to countermand prior instructions.
//! OWASP LLM01 / ATLAS AML.T0051.000.

use super::{match_signatures, normalize, Category, Detection, Detector};
use crate::signatures::Signature;

pub struct InstructionOverride {
    sigs: Vec<Signature>,
}

impl InstructionOverride {
    pub fn new(sigs: Vec<Signature>) -> Self {
        Self { sigs }
    }
}

impl Detector for InstructionOverride {
    fn name(&self) -> &'static str {
        "instruction_override"
    }
    fn category(&self) -> Category {
        Category::InstructionOverride
    }
    fn scan(&self, input: &str) -> Vec<Detection> {
        // Override attacks hide in spacing/zero-width chars, so normalize first.
        let normalized = normalize(input);
        match_signatures(&normalized, &self.sigs, self.name(), false)
    }
}
