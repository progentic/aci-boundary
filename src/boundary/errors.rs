use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BoundaryError {
    #[error("Payload size threshold exceeded: {0} bytes (max {1})")]
    PayloadLimitExceeded(usize, usize),

    #[error("Malicious null-byte sequence detected")]
    NullByteDetected,

    #[error("Path specification violation: path cannot be empty, absolute, or traverse out of bounds")]
    InvalidPathSpecification,

    #[error("Symlink escalation or breakout from workspace root detected during ancestry descent")]
    SymlinkEscalation,

    #[error("Malformed provider output payload: {0}")]
    MalformedProviderPayload(String),

    #[error("Capability not authorized by active scope manifest: {0}")]
    CapabilityProhibited(String),

    #[error("Invalid test suite target format: must be clean alphanumeric layout")]
    InvalidTestSuiteName,

    #[error("Policy gate enforcement denial: {0}")]
    PolicyDenial(String),

    #[error("Cryptographic digital signature verification failed for human approval proof")]
    InvalidHumanApprovalProof,

    #[error("Mandatory audit logging system failure: {0}. Failing closed.")]
    AuditSystemFailure(String),

    #[error("Underlying workspace storage access error: {0}")]
    StorageAccessError(String),

    #[error("Malformed input identifier wrapper string: {0}")]
    InvalidIdentifier(String),

    #[error("Malformed hex hash or signature structure: {0}")]
    InvalidCryptographicFormat(String),
}
