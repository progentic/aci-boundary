#[cfg(test)]
mod error_variant_coverage {
    use crate::boundary::audit::AuditOutcome;
    use crate::boundary::errors::BoundaryError;
    use crate::boundary::manifest::ToolCapability;

    // This is not the coordinator's runtime mapping table.
    // It is a compile-time exhaustiveness tripwire for BoundaryError variants.
    fn classify_boundary_error(err: BoundaryError) -> Option<AuditOutcome> {
        match err {
            BoundaryError::AuditSystemFailure(_) => None,
            BoundaryError::PayloadLimitExceeded(_, _) => Some(AuditOutcome::ValidationDenied {
                proposed_capability: ToolCapability::ReadFile,
                reason: String::new(),
            }),
            BoundaryError::NullByteDetected => Some(AuditOutcome::ValidationDenied {
                proposed_capability: ToolCapability::ReadFile,
                reason: String::new(),
            }),
            BoundaryError::InvalidPathSpecification => Some(AuditOutcome::ValidationDenied {
                proposed_capability: ToolCapability::ReadFile,
                reason: String::new(),
            }),
            BoundaryError::SymlinkEscalation => Some(AuditOutcome::ExecutionFailed {
                error: String::new(),
            }),
            BoundaryError::MalformedProviderPayload(_) => Some(AuditOutcome::ParseDenied {
                reason: String::new(),
            }),
            BoundaryError::CapabilityProhibited(_) => Some(AuditOutcome::ValidationDenied {
                proposed_capability: ToolCapability::ReadFile,
                reason: String::new(),
            }),
            BoundaryError::InvalidTestSuiteName => Some(AuditOutcome::ValidationDenied {
                proposed_capability: ToolCapability::ExecuteCargoTests,
                reason: String::new(),
            }),
            BoundaryError::PolicyDenial(_) => Some(AuditOutcome::PolicyDenied {
                reason: String::new(),
            }),
            BoundaryError::InvalidHumanApprovalProof => Some(AuditOutcome::PolicyDenied {
                reason: String::new(),
            }),
            BoundaryError::StorageAccessError(_) => Some(AuditOutcome::ExecutionFailed {
                error: String::new(),
            }),
            BoundaryError::InvalidIdentifier(_) => Some(AuditOutcome::ValidationDenied {
                proposed_capability: ToolCapability::ReadFile,
                reason: String::new(),
            }),
            BoundaryError::InvalidCryptographicFormat(_) => Some(AuditOutcome::ValidationDenied {
                proposed_capability: ToolCapability::ReadFile,
                reason: String::new(),
            }),
        }
    }

    #[test]
    fn test_exhaustive_error_classification() {
        let cases = vec![
            BoundaryError::PayloadLimitExceeded(0, 0),
            BoundaryError::NullByteDetected,
            BoundaryError::InvalidPathSpecification,
            BoundaryError::SymlinkEscalation,
            BoundaryError::MalformedProviderPayload("x".into()),
            BoundaryError::CapabilityProhibited("x".into()),
            BoundaryError::InvalidTestSuiteName,
            BoundaryError::PolicyDenial("x".into()),
            BoundaryError::InvalidHumanApprovalProof,
            BoundaryError::StorageAccessError("x".into()),
            BoundaryError::InvalidIdentifier("x".into()),
            BoundaryError::InvalidCryptographicFormat("x".into()),
        ];

        for err in cases {
            assert!(classify_boundary_error(err).is_some());
        }

        assert!(classify_boundary_error(BoundaryError::AuditSystemFailure("x".into())).is_none());
    }
}
