use std::path::{Path, PathBuf};

use crate::boundary::errors::BoundaryError;
use crate::boundary::tool::{ValidatedToolInvocation, ValidatedToolInvocationKind};
use crate::boundary::workspace::WorkspaceRoot;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct RuntimeEnvironment {
    cargo_path: PathBuf,
}

impl RuntimeEnvironment {
    pub fn try_new(path: PathBuf) -> Result<Self, BoundaryError> {
        if !path.is_absolute() {
            return Err(BoundaryError::PolicyDenial(
                "Runtime tool path must be absolute".into(),
            ));
        }
        let canonical_path = path.canonicalize().map_err(|e| {
            BoundaryError::StorageAccessError(format!("Invalid runtime tool path: {e}"))
        })?;

        let meta = std::fs::metadata(&canonical_path).map_err(|e| {
            BoundaryError::StorageAccessError(format!("Invalid runtime tool path: {e}"))
        })?;

        if !meta.is_file() {
            return Err(BoundaryError::PolicyDenial(
                "Runtime tool path must point to a file".into(),
            ));
        }

        #[cfg(unix)]
        {
            if meta.permissions().mode() & 0o111 == 0 {
                return Err(BoundaryError::PolicyDenial(
                    "Runtime tool path is not executable".into(),
                ));
            }
        }

        Ok(Self {
            cargo_path: canonical_path,
        })
    }

    pub fn cargo_path(&self) -> &Path {
        &self.cargo_path
    }
}

pub struct NarrowExecutionAdapter {
    workspace: WorkspaceRoot,
    runtime: RuntimeEnvironment,
}

impl NarrowExecutionAdapter {
    pub fn new(workspace: WorkspaceRoot, runtime: RuntimeEnvironment) -> Self {
        Self { workspace, runtime }
    }

    pub(in crate::boundary) async fn execute(
        &self,
        invocation: ValidatedToolInvocation,
    ) -> Result<String, BoundaryError> {
        match invocation.kind {
            ValidatedToolInvocationKind::ReadFile { path } => {
                let absolute = self.workspace.resolve_and_verify_anchor(&path)?;

                let meta = std::fs::metadata(&absolute)
                    .map_err(|e| BoundaryError::StorageAccessError(e.to_string()))?;
                if !meta.is_file() {
                    return Err(BoundaryError::PolicyDenial(
                        "ReadFile execution requires an active file target, not a directory".into(),
                    ));
                }

                tokio::fs::read_to_string(absolute)
                    .await
                    .map_err(|e| BoundaryError::StorageAccessError(e.to_string()))
            }
            ValidatedToolInvocationKind::WriteFile { path, content } => {
                let absolute = self.workspace.resolve_and_verify_anchor(&path)?;

                if absolute.exists() {
                    let meta = std::fs::metadata(&absolute)
                        .map_err(|e| BoundaryError::StorageAccessError(e.to_string()))?;
                    if meta.is_dir() {
                        return Err(BoundaryError::PolicyDenial(
                            "Write path maps directly to a pre-existing directory structure".into(),
                        ));
                    }
                }

                let parent_dir = absolute.parent().ok_or(BoundaryError::SymlinkEscalation)?;
                let temp_path = parent_dir.join(format!(".tmp-aci-file-{}", uuid::Uuid::new_v4()));

                let mut file = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp_path)
                    .await
                    .map_err(|e| BoundaryError::StorageAccessError(e.to_string()))?;

                use tokio::io::AsyncWriteExt;
                file.write_all(content.into_inner().as_bytes())
                    .await
                    .map_err(|e| BoundaryError::StorageAccessError(e.to_string()))?;
                file.sync_all()
                    .await
                    .map_err(|e| BoundaryError::StorageAccessError(e.to_string()))?;
                drop(file);

                tokio::fs::rename(&temp_path, &absolute)
                    .await
                    .map_err(|e| {
                        let _ = std::fs::remove_file(&temp_path);
                        BoundaryError::StorageAccessError(e.to_string())
                    })?;

                Ok("Storage modification write processed".into())
            }
            ValidatedToolInvocationKind::RunTests { test_suite } => {
                let execution_output = tokio::process::Command::new(self.runtime.cargo_path())
                    .current_dir(self.workspace.root_path())
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .arg("test")
                    .arg("--test")
                    .arg(test_suite.as_str())
                    .output()
                    .await
                    .map_err(|e| BoundaryError::StorageAccessError(e.to_string()))?;

                Ok(String::from_utf8_lossy(&execution_output.stdout).to_string())
            }
        }
    }
}
