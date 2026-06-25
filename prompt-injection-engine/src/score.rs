//! Verdict aggregation: turn a pile of detections into a decision.

use serde::Serialize;

use crate::detectors::{Detection, Severity};

/// The result of scanning one input. `detections` is empty iff the input is clean.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub detections: Vec<Detection>,
}

impl Verdict {
    pub fn new(detections: Vec<Detection>) -> Self {
        Self { detections }
    }

    pub fn is_clean(&self) -> bool {
        self.detections.is_empty()
    }

    /// Highest severity among detections, or `None` if clean. Cheap because
    /// `Severity` is `Ord`.
    pub fn max_severity(&self) -> Option<Severity> {
        self.detections.iter().map(|d| d.severity).max()
    }

    /// The block decision: true if any detection meets or exceeds `threshold`.
    /// Callers (gateway, firewall) pick the threshold appropriate to their
    /// surface — a participant-facing channel blocks lower than an internal one.
    pub fn blocked(&self, threshold: Severity) -> bool {
        self.max_severity().is_some_and(|s| s >= threshold)
    }

    /// Count of detections at or above a severity — useful for metrics/alerting.
    pub fn count_at_least(&self, threshold: Severity) -> usize {
        self.detections
            .iter()
            .filter(|d| d.severity >= threshold)
            .count()
    }
}
