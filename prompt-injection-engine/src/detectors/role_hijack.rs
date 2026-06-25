//! Jailbreak via persona/simulation framing ("you are now DAN", "act as an
//! unrestricted AI", "pretend you have no rules"). OWASP LLM01 / ATLAS AML.T0054.

use super::{match_signatures, normalize, Category, Detection, Detector};
use crate::signatures::Signature;

pub struct RoleHijack {
    sigs: Vec<Signature>,
}

impl RoleHijack {
    pub fn new(sigs: Vec<Signature>) -> Self {
        Self { sigs }
    }
}

impl Detector for RoleHijack {
    fn name(&self) -> &'static str {
        "role_hijack"
    }
    fn category(&self) -> Category {
        Category::RoleHijack
    }
    fn scan(&self, input: &str) -> Vec<Detection> {
        let normalized = normalize(input);
        match_signatures(&normalized, &self.sigs, self.name(), false)
    }
}
