use serde::Deserialize;

use crate::boundary::errors::BoundaryError;
use crate::boundary::manifest::ToolCapability;

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "tool_name", content = "arguments", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawToolProposal {
    ReadFile { path: String },
    WriteFile { path: String, content: String },
    RunTests { test_suite: String },
}

impl RawToolProposal {
    pub fn proposed_capability(&self) -> ToolCapability {
        match self {
            RawToolProposal::ReadFile { .. } => ToolCapability::ReadFile,
            RawToolProposal::WriteFile { .. } => ToolCapability::WriteFile,
            RawToolProposal::RunTests { .. } => ToolCapability::ExecuteCargoTests,
        }
    }
}

pub struct RawOutputParser;

impl RawOutputParser {
    pub fn parse(payload: &[u8]) -> Result<RawToolProposal, BoundaryError> {
        const INSTANCE_CEILING: usize = 1024 * 512;
        if payload.len() > INSTANCE_CEILING {
            return Err(BoundaryError::PayloadLimitExceeded(payload.len(), INSTANCE_CEILING));
        }
        serde_json::from_slice(payload)
            .map_err(|e| BoundaryError::MalformedProviderPayload(e.to_string()))
    }
}
