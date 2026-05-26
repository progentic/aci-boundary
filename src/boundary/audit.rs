use crate::boundary::errors::BoundaryError;
use crate::boundary::identifiers::{ManifestId, SessionId};
use crate::boundary::manifest::ToolCapability;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum AuditOutcome {
    ParseDenied {
        reason: String,
    },
    ValidationDenied {
        proposed_capability: ToolCapability,
        reason: String,
    },
    PolicyDenied {
        reason: String,
    },
    ApprovalConsumptionFailed {
        reason: String,
    },
    ExecutionStarted {
        capability: ToolCapability,
    },
    ExecutionSucceeded {
        capability: ToolCapability,
    },
    ExecutionFailed {
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditRecord {
    pub event_id: String,
    pub sequence_number: u64,
    pub timestamp: u64,
    pub session_id: SessionId,
    pub manifest_id: ManifestId,
    pub raw_proposal_hash: String,
    pub outcome: AuditOutcome,
}

pub trait AuditSink {
    /// Returning Ok(()) means the record has been durably emitted or flushed
    /// to persistent storage and should survive process termination.
    fn emit_record(&self, record: AuditRecord) -> Result<(), BoundaryError>;
}
