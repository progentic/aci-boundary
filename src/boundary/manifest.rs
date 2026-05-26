use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::boundary::errors::BoundaryError;
use crate::boundary::identifiers::{ManifestHash, ManifestId};
use crate::boundary::types::IsolatedPath;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum ToolCapability {
    ReadFile,
    WriteFile,
    ExecuteCargoTests,
}

impl ToolCapability {
    pub fn wire_name(&self) -> &'static str {
        match self {
            ToolCapability::ReadFile => "read_file",
            ToolCapability::WriteFile => "write_file",
            ToolCapability::ExecuteCargoTests => "execute_cargo_tests",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathScope {
    ExactFile(IsolatedPath),
    DirectoryTree(IsolatedPath),
}

impl PathScope {
    pub fn authorizes(&self, requested: &IsolatedPath) -> bool {
        match self {
            PathScope::ExactFile(allowed) => allowed == requested,
            PathScope::DirectoryTree(allowed_dir) => {
                requested != allowed_dir && requested.as_path().starts_with(allowed_dir.as_path())
            }
        }
    }
}

#[derive(serde::Serialize, PartialEq, Eq, PartialOrd, Ord)]
enum CanonicalPathScope {
    ExactFile { components: Vec<String> },
    DirectoryTree { components: Vec<String> },
}

impl From<&PathScope> for CanonicalPathScope {
    fn from(scope: &PathScope) -> Self {
        match scope {
            PathScope::ExactFile(path) => CanonicalPathScope::ExactFile {
                components: path.to_canonical_components(),
            },
            PathScope::DirectoryTree(path) => CanonicalPathScope::DirectoryTree {
                components: path.to_canonical_components(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

impl Environment {
    pub fn wire_name(&self) -> &'static str {
        match self {
            Environment::Development => "development",
            Environment::Staging => "staging",
            Environment::Production => "production",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScopeManifest {
    pub manifest_id: ManifestId,
    pub environment: Environment,
    pub allowed_capabilities: BTreeSet<ToolCapability>,
    pub read_scopes: BTreeSet<PathScope>,
    pub write_scopes: BTreeSet<PathScope>,
    pub step_budget: u32,
}

#[derive(serde::Serialize)]
struct CanonicalManifestRepresentation<'a> {
    manifest_id: &'a str,
    environment: &'a str,
    allowed_capabilities: Vec<&'a str>,
    read_scopes: BTreeSet<CanonicalPathScope>,
    write_scopes: BTreeSet<CanonicalPathScope>,
    step_budget: u32,
}

impl ScopeManifest {
    pub fn compute_canonical_hash(&self) -> Result<ManifestHash, BoundaryError> {
        let mut caps: Vec<&str> = self
            .allowed_capabilities
            .iter()
            .map(|c| c.wire_name())
            .collect();
        caps.sort_unstable();

        let structural_state = CanonicalManifestRepresentation {
            manifest_id: self.manifest_id.as_str(),
            environment: self.environment.wire_name(),
            allowed_capabilities: caps,
            read_scopes: self.read_scopes.iter().map(Into::into).collect(),
            write_scopes: self.write_scopes.iter().map(Into::into).collect(),
            step_budget: self.step_budget,
        };

        let serialized = serde_json::to_vec(&structural_state)
            .map_err(|e| BoundaryError::PolicyDenial(e.to_string()))?;
        let hash_hex = format!("{:x}", Sha256::digest(&serialized));
        ManifestHash::try_from(hash_hex)
    }
}
