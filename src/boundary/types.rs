use std::path::{Component, Path, PathBuf};

use crate::boundary::errors::BoundaryError;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct IsolatedPath(PathBuf);

impl TryFrom<String> for IsolatedPath {
    type Error = BoundaryError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        if raw.is_empty() || raw.contains('\0') {
            return Err(BoundaryError::InvalidPathSpecification);
        }
        if raw.len() > 4096 {
            return Err(BoundaryError::PayloadLimitExceeded(raw.len(), 4096));
        }

        let path = Path::new(&raw);
        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::Prefix(_)))
        {
            return Err(BoundaryError::InvalidPathSpecification);
        }

        let mut cleaned = PathBuf::new();
        for component in path.components() {
            match component {
                Component::ParentDir => return Err(BoundaryError::InvalidPathSpecification),
                Component::Normal(p) => cleaned.push(p),
                Component::CurDir | Component::RootDir => {}
                Component::Prefix(_) => return Err(BoundaryError::InvalidPathSpecification),
            }
        }

        if cleaned.as_os_str().is_empty() {
            return Err(BoundaryError::InvalidPathSpecification);
        }

        Ok(Self(cleaned))
    }
}

impl IsolatedPath {
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn to_canonical_components(&self) -> Vec<String> {
        self.0
            .components()
            .filter_map(|c| match c {
                Component::Normal(os_str) => Some(os_str.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FileContent(String);

impl TryFrom<String> for FileContent {
    type Error = BoundaryError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        if raw.contains('\0') {
            return Err(BoundaryError::NullByteDetected);
        }
        if raw.len() > 1024 * 1024 * 2 {
            return Err(BoundaryError::PayloadLimitExceeded(raw.len(), 1024 * 1024 * 2));
        }
        Ok(Self(raw))
    }
}

impl FileContent {
    pub fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TestSuiteName(String);

impl TryFrom<String> for TestSuiteName {
    type Error = BoundaryError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        if raw.is_empty() || raw.len() > 128 || raw.starts_with('-') {
            return Err(BoundaryError::InvalidTestSuiteName);
        }
        let is_valid = raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !is_valid {
            return Err(BoundaryError::InvalidTestSuiteName);
        }
        Ok(Self(raw))
    }
}

impl TestSuiteName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
