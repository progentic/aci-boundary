use std::path::{Component, Path, PathBuf};

use crate::boundary::errors::BoundaryError;
use crate::boundary::types::IsolatedPath;

pub struct WorkspaceRoot {
    root_path: PathBuf,
}

impl WorkspaceRoot {
    pub fn try_new(base_path: PathBuf) -> Result<Self, std::io::Error> {
        let canonical = base_path.canonicalize()?;
        Ok(Self {
            root_path: canonical,
        })
    }

    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    pub fn resolve_and_verify_anchor(
        &self,
        relative_path: &IsolatedPath,
    ) -> Result<PathBuf, BoundaryError> {
        let mut current_resolved = self.root_path.clone();

        for component in relative_path.as_path().components() {
            if let Component::Normal(os_str) = component {
                current_resolved.push(os_str);

                match std::fs::symlink_metadata(&current_resolved) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            let link_target = std::fs::read_link(&current_resolved)
                                .map_err(|e| BoundaryError::StorageAccessError(e.to_string()))?;

                            let absolute_link = if link_target.is_absolute() {
                                link_target
                            } else {
                                current_resolved
                                    .parent()
                                    .unwrap_or(&self.root_path)
                                    .join(link_target)
                            };

                            let canonicalized = absolute_link
                                .canonicalize()
                                .map_err(|_| BoundaryError::SymlinkEscalation)?;

                            if !canonicalized.starts_with(&self.root_path) {
                                return Err(BoundaryError::SymlinkEscalation);
                            }
                            current_resolved = canonicalized;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if !current_resolved.starts_with(&self.root_path) {
                            return Err(BoundaryError::SymlinkEscalation);
                        }
                    }
                    Err(io_err) => {
                        return Err(BoundaryError::StorageAccessError(io_err.to_string()))
                    }
                }
            }
        }

        if current_resolved.exists() {
            let fully_canonical = current_resolved
                .canonicalize()
                .map_err(|_| BoundaryError::SymlinkEscalation)?;
            if !fully_canonical.starts_with(&self.root_path) {
                return Err(BoundaryError::SymlinkEscalation);
            }
        }

        Ok(current_resolved)
    }
}
