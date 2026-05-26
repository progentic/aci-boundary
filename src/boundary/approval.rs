use crate::boundary::errors::BoundaryError;
use crate::boundary::identifiers::{
    ActorId, ApprovalId, ApprovalIssuerId, ApprovalSignature, InvocationHash, ManifestHash,
    SessionId, TicketReference,
};
use crate::boundary::manifest::ToolCapability;

#[derive(Debug, Clone, serde::Serialize)]
pub struct HumanApprovalProof {
    pub approval_id: ApprovalId,
    pub issuer_id: ApprovalIssuerId,
    pub approver_identity: ActorId,
    pub session_id: SessionId,
    pub expected_manifest_hash: ManifestHash,
    pub expected_invocation_hash: InvocationHash,
    pub capability: ToolCapability,
    pub ticket_reference: TicketReference,
    pub approval_version: u32,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: ApprovalSignature,
}

pub struct ApprovalVerificationContext<'a> {
    pub session_id: &'a SessionId,
    pub manifest_hash: &'a ManifestHash,
    pub invocation_hash: &'a InvocationHash,
    pub capability: ToolCapability,
    pub current_time: u64,
}

pub trait ApprovalKeyring {
    fn public_key_for_issuer(
        &self,
        issuer: &ApprovalIssuerId,
    ) -> Result<ed25519_dalek::VerifyingKey, BoundaryError>;

    fn issuer_is_authorized_for_capability(
        &self,
        issuer: &ApprovalIssuerId,
        capability: ToolCapability,
    ) -> Result<(), BoundaryError>;

    fn actor_is_authorized_for_capability(
        &self,
        actor: &ActorId,
        capability: ToolCapability,
    ) -> Result<(), BoundaryError>;
}

pub trait ApprovalStateStore {
    fn is_ticket_active(&self, ticket: &TicketReference) -> Result<(), BoundaryError>;

    fn reserve_approval(
        &self,
        approval_id: &ApprovalId,
        reservation_ttl_secs: u64,
    ) -> Result<(), BoundaryError>;

    fn consume_reserved_approval(&self, approval_id: &ApprovalId) -> Result<(), BoundaryError>;

    fn release_reserved_approval(&self, approval_id: &ApprovalId) -> Result<(), BoundaryError>;
}

pub trait ApprovalVerifier {
    fn verify_approval(
        &self,
        proof: &HumanApprovalProof,
        context: &ApprovalVerificationContext,
    ) -> Result<(), BoundaryError>;
}

pub struct Ed25519TicketingVerifier<K> {
    keyring: K,
}

impl<K: ApprovalKeyring> Ed25519TicketingVerifier<K> {
    pub fn new(keyring: K) -> Self {
        Self { keyring }
    }
}

impl<K: ApprovalKeyring> ApprovalVerifier for Ed25519TicketingVerifier<K> {
    fn verify_approval(
        &self,
        proof: &HumanApprovalProof,
        context: &ApprovalVerificationContext,
    ) -> Result<(), BoundaryError> {
        if proof.approval_version != 1 {
            return Err(BoundaryError::InvalidHumanApprovalProof);
        }

        if proof.session_id != *context.session_id {
            return Err(BoundaryError::PolicyDenial("Session ID mismatch".into()));
        }
        if proof.expected_manifest_hash != *context.manifest_hash {
            return Err(BoundaryError::PolicyDenial("Manifest hash mismatch".into()));
        }
        if proof.expected_invocation_hash != *context.invocation_hash {
            return Err(BoundaryError::PolicyDenial(
                "Invocation hash mismatch".into(),
            ));
        }
        if proof.capability != context.capability {
            return Err(BoundaryError::PolicyDenial("Capability mismatch".into()));
        }

        if context.current_time > proof.expires_at {
            return Err(BoundaryError::PolicyDenial("Approval token expired".into()));
        }
        if context.current_time < proof.issued_at {
            return Err(BoundaryError::PolicyDenial(
                "Approval token issued in future".into(),
            ));
        }

        self.keyring
            .issuer_is_authorized_for_capability(&proof.issuer_id, context.capability)?;
        self.keyring
            .actor_is_authorized_for_capability(&proof.approver_identity, context.capability)?;

        let canonical_message = [
            format!("approval_version={}", proof.approval_version),
            format!("approval_id={}", proof.approval_id.as_str()),
            format!("issuer_id={}", proof.issuer_id.as_str()),
            format!("approver_identity={}", proof.approver_identity.as_str()),
            format!("session_id={}", proof.session_id.as_str()),
            format!("manifest_hash={}", proof.expected_manifest_hash.as_str()),
            format!(
                "invocation_hash={}",
                proof.expected_invocation_hash.as_str()
            ),
            format!("capability={}", proof.capability.wire_name()),
            format!("ticket_reference={}", proof.ticket_reference.as_str()),
            format!("issued_at={}", proof.issued_at),
            format!("expires_at={}", proof.expires_at),
        ]
        .join("\n");

        let signature_bytes = hex::decode(proof.signature.as_str())
            .map_err(|_| BoundaryError::InvalidHumanApprovalProof)?;
        let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
            .map_err(|_| BoundaryError::InvalidHumanApprovalProof)?;
        let verifying_key = self.keyring.public_key_for_issuer(&proof.issuer_id)?;

        verifying_key
            .verify_strict(canonical_message.as_bytes(), &signature)
            .map_err(|_| BoundaryError::InvalidHumanApprovalProof)?;

        Ok(())
    }
}
