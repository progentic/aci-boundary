use sha2::{Digest, Sha256};

use crate::boundary::errors::BoundaryError;
use crate::boundary::identifiers::InvocationHash;
use crate::boundary::llm::RawToolProposal;
use crate::boundary::manifest::{ScopeManifest, ToolCapability};
use crate::boundary::types::{FileContent, IsolatedPath, TestSuiteName};

#[derive(Debug, Clone, serde::Serialize)]
pub(in crate::boundary) enum ValidatedToolInvocationKind {
    ReadFile {
        path: IsolatedPath,
    },
    WriteFile {
        path: IsolatedPath,
        content: FileContent,
    },
    RunTests {
        test_suite: TestSuiteName,
    },
}

#[derive(Debug, Clone)]
pub(in crate::boundary) struct ValidatedToolInvocation {
    pub(in crate::boundary) kind: ValidatedToolInvocationKind,
    invocation_hash: InvocationHash,
}

#[derive(serde::Serialize)]
struct CanonicalInvocationIdentity {
    capability: &'static str,
    path_components: Option<Vec<String>>,
    test_suite: Option<String>,
    content_sha256: Option<String>,
}

impl ValidatedToolInvocation {
    pub(in crate::boundary) fn capability(&self) -> ToolCapability {
        match &self.kind {
            ValidatedToolInvocationKind::ReadFile { .. } => ToolCapability::ReadFile,
            ValidatedToolInvocationKind::WriteFile { .. } => ToolCapability::WriteFile,
            ValidatedToolInvocationKind::RunTests { .. } => ToolCapability::ExecuteCargoTests,
        }
    }

    pub(in crate::boundary) fn invocation_hash(&self) -> &InvocationHash {
        &self.invocation_hash
    }

    pub(in crate::boundary) fn try_from_proposal(
        proposal: RawToolProposal,
        manifest: &ScopeManifest,
    ) -> Result<Self, BoundaryError> {
        let proposed_cap = proposal.proposed_capability();
        if !manifest.allowed_capabilities.contains(&proposed_cap) {
            return Err(BoundaryError::CapabilityProhibited(
                proposed_cap.wire_name().to_string(),
            ));
        }

        let kind = match proposal {
            RawToolProposal::ReadFile { path } => {
                let isolated = IsolatedPath::try_from(path)?;
                if !manifest
                    .read_scopes
                    .iter()
                    .any(|scope| scope.authorizes(&isolated))
                {
                    return Err(BoundaryError::PolicyDenial(
                        "Read target unauthorized by path-scope checks".into(),
                    ));
                }
                ValidatedToolInvocationKind::ReadFile { path: isolated }
            }
            RawToolProposal::WriteFile { path, content } => {
                let isolated = IsolatedPath::try_from(path)?;
                let validated_content = FileContent::try_from(content)?;
                if !manifest
                    .write_scopes
                    .iter()
                    .any(|scope| scope.authorizes(&isolated))
                {
                    return Err(BoundaryError::PolicyDenial(
                        "Write target unauthorized by path-scope checks".into(),
                    ));
                }
                ValidatedToolInvocationKind::WriteFile {
                    path: isolated,
                    content: validated_content,
                }
            }
            RawToolProposal::RunTests { test_suite } => {
                let validated_suite = TestSuiteName::try_from(test_suite)?;
                ValidatedToolInvocationKind::RunTests {
                    test_suite: validated_suite,
                }
            }
        };

        let mut identity = CanonicalInvocationIdentity {
            capability: proposed_cap.wire_name(),
            path_components: None,
            test_suite: None,
            content_sha256: None,
        };

        match &kind {
            ValidatedToolInvocationKind::ReadFile { path } => {
                identity.path_components = Some(path.to_canonical_components());
            }
            ValidatedToolInvocationKind::WriteFile { path, content } => {
                identity.path_components = Some(path.to_canonical_components());
                let raw_bytes = serde_json::to_vec(content)
                    .map_err(|e| BoundaryError::PolicyDenial(e.to_string()))?;
                identity.content_sha256 = Some(format!("{:x}", Sha256::digest(&raw_bytes)));
            }
            ValidatedToolInvocationKind::RunTests { test_suite } => {
                identity.test_suite = Some(test_suite.as_str().to_string());
            }
        };

        let serialized_identity = serde_json::to_vec(&identity)
            .map_err(|e| BoundaryError::PolicyDenial(e.to_string()))?;
        let hash_hex = format!("{:x}", Sha256::digest(&serialized_identity));
        let invocation_hash = InvocationHash::try_from(hash_hex)?;

        Ok(Self {
            kind,
            invocation_hash,
        })
    }
}
