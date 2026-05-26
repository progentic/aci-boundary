pub mod approval;
pub mod audit;
pub mod errors;
pub mod identifiers;
pub mod manifest;
pub mod types;
pub mod workspace;

mod executor;
mod llm;
mod tool;

use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::boundary::approval::{ApprovalStateStore, ApprovalVerifier, HumanApprovalProof};
use crate::boundary::audit::{AuditOutcome, AuditRecord, AuditSink};
use crate::boundary::errors::BoundaryError;
use crate::boundary::identifiers::{ApprovalId, SessionId};
use crate::boundary::llm::RawOutputParser;
use crate::boundary::manifest::{Environment, ScopeManifest, ToolCapability};
use crate::boundary::tool::ValidatedToolInvocation;

pub use crate::boundary::executor::{NarrowExecutionAdapter, RuntimeEnvironment};

enum ApprovalReservation {
    NotRequired,
    Reserved { approval_id: ApprovalId },
}

pub struct BoundaryRuntimePolicy {
    pub approval_reservation_ttl_secs: u64,
}

struct PolicyGate;

impl PolicyGate {
    fn verify_and_reserve(
        invocation: &ValidatedToolInvocation,
        manifest: &ScopeManifest,
        session_id: &SessionId,
        current_time: u64,
        approval_proof: Option<&HumanApprovalProof>,
        verifier: &dyn ApprovalVerifier,
        state_store: &dyn ApprovalStateStore,
        policy: &BoundaryRuntimePolicy,
    ) -> Result<ApprovalReservation, BoundaryError> {
        if manifest.environment == Environment::Production
            && matches!(
                invocation.capability(),
                ToolCapability::WriteFile | ToolCapability::ExecuteCargoTests
            )
        {
            let proof = approval_proof.ok_or_else(|| {
                BoundaryError::PolicyDenial(
                    "Production mutations require explicit authorization signatures".into(),
                )
            })?;

            let canonical_manifest_hash = manifest.compute_canonical_hash()?;

            let verification_context = crate::boundary::approval::ApprovalVerificationContext {
                session_id,
                manifest_hash: &canonical_manifest_hash,
                invocation_hash: invocation.invocation_hash(),
                capability: invocation.capability(),
                current_time,
            };

            verifier.verify_approval(proof, &verification_context)?;
            state_store.is_ticket_active(&proof.ticket_reference)?;

            state_store.reserve_approval(
                &proof.approval_id,
                policy.approval_reservation_ttl_secs,
            )?;

            return Ok(ApprovalReservation::Reserved {
                approval_id: proof.approval_id.clone(),
            });
        }
        Ok(ApprovalReservation::NotRequired)
    }
}

pub struct ExecutionCoordinator<'a> {
    pub session_id: SessionId,
    pub current_sequence: &'a mut u64,
    pub remaining_step_budget: &'a mut u32,
    pub audit_sink: &'a dyn AuditSink,
    pub verifier: &'a dyn ApprovalVerifier,
    pub state_store: &'a dyn ApprovalStateStore,
    pub executor: &'a NarrowExecutionAdapter,
    pub policy: &'a BoundaryRuntimePolicy,
}

fn emit_audit(
    sink: &dyn AuditSink,
    sequence: u64,
    timestamp: u64,
    session_id: &SessionId,
    manifest: &ScopeManifest,
    proposal_hash: &str,
    outcome: AuditOutcome,
    failure_context: &str,
) -> Result<(), BoundaryError> {
    sink.emit_record(AuditRecord {
        event_id: uuid::Uuid::new_v4().to_string(),
        sequence_number: sequence,
        timestamp,
        session_id: session_id.clone(),
        manifest_id: manifest.manifest_id.clone(),
        raw_proposal_hash: proposal_hash.to_string(),
        outcome,
    })
    .map_err(|audit_err| {
        BoundaryError::AuditSystemFailure(format!("{failure_context}: {audit_err}"))
    })
}

pub async fn run_isolated_pipeline_step(
    raw_payload: &[u8],
    manifest: &ScopeManifest,
    approval: Option<&HumanApprovalProof>,
    coordinator: ExecutionCoordinator<'_>,
) -> Result<String, BoundaryError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| BoundaryError::PolicyDenial(format!("System clock before UNIX epoch: {e}")))?
        .as_secs();

    let proposal_hash = format!("{:x}", Sha256::digest(raw_payload));

    if *coordinator.remaining_step_budget == 0 {
        let err = BoundaryError::PolicyDenial("Transaction step budget exhausted".into());
        emit_audit(
            coordinator.audit_sink,
            *coordinator.current_sequence,
            timestamp,
            &coordinator.session_id,
            manifest,
            &proposal_hash,
            AuditOutcome::PolicyDenied {
                reason: err.to_string(),
            },
            "Terminal budget denial logging failed",
        )?;
        *coordinator.current_sequence += 1;
        return Err(err);
    }
    *coordinator.remaining_step_budget -= 1;

    let raw_proposal = match RawOutputParser::parse(raw_payload) {
        Ok(prop) => prop,
        Err(e) => {
            emit_audit(
                coordinator.audit_sink,
                *coordinator.current_sequence,
                timestamp,
                &coordinator.session_id,
                manifest,
                &proposal_hash,
                AuditOutcome::ParseDenied {
                    reason: e.to_string(),
                },
                "Terminal parse denial logging failed",
            )?;
            *coordinator.current_sequence += 1;
            return Err(e);
        }
    };

    let proposed_capability = raw_proposal.proposed_capability();

    let invocation = match ValidatedToolInvocation::try_from_proposal(raw_proposal, manifest) {
        Ok(inv) => inv,
        Err(e) => {
            emit_audit(
                coordinator.audit_sink,
                *coordinator.current_sequence,
                timestamp,
                &coordinator.session_id,
                manifest,
                &proposal_hash,
                AuditOutcome::ValidationDenied {
                    proposed_capability,
                    reason: e.to_string(),
                },
                "Terminal validation denial logging failed",
            )?;
            *coordinator.current_sequence += 1;
            return Err(e);
        }
    };

    let reservation = match PolicyGate::verify_and_reserve(
        &invocation,
        manifest,
        &coordinator.session_id,
        timestamp,
        approval,
        coordinator.verifier,
        coordinator.state_store,
        coordinator.policy,
    ) {
        Ok(res) => res,
        Err(e) => {
            emit_audit(
                coordinator.audit_sink,
                *coordinator.current_sequence,
                timestamp,
                &coordinator.session_id,
                manifest,
                &proposal_hash,
                AuditOutcome::PolicyDenied {
                    reason: e.to_string(),
                },
                "Terminal policy denial logging failed",
            )?;
            *coordinator.current_sequence += 1;
            return Err(e);
        }
    };

    if let Err(audit_err) = emit_audit(
        coordinator.audit_sink,
        *coordinator.current_sequence,
        timestamp,
        &coordinator.session_id,
        manifest,
        &proposal_hash,
        AuditOutcome::ExecutionStarted {
            capability: proposed_capability,
        },
        "Pre-execution audit logging failed",
    ) {
        if let ApprovalReservation::Reserved { approval_id } = &reservation {
            let _ = coordinator.state_store.release_reserved_approval(approval_id);
        }
        return Err(audit_err);
    }
    *coordinator.current_sequence += 1;

    if let ApprovalReservation::Reserved { approval_id } = reservation {
        if let Err(e) = coordinator.state_store.consume_reserved_approval(&approval_id) {
            emit_audit(
                coordinator.audit_sink,
                *coordinator.current_sequence,
                timestamp,
                &coordinator.session_id,
                manifest,
                &proposal_hash,
                AuditOutcome::ApprovalConsumptionFailed {
                    reason: e.to_string(),
                },
                "Failed to log consumption failure",
            )?;
            *coordinator.current_sequence += 1;
            return Err(e);
        }
    }

    match coordinator.executor.execute(invocation).await {
        Ok(output_message) => {
            emit_audit(
                coordinator.audit_sink,
                *coordinator.current_sequence,
                timestamp,
                &coordinator.session_id,
                manifest,
                &proposal_hash,
                AuditOutcome::ExecutionSucceeded {
                    capability: proposed_capability,
                },
                "Execution succeeded, but completion audit failed",
            )?;
            *coordinator.current_sequence += 1;
            Ok(output_message)
        }
        Err(err) => {
            let audit_result = emit_audit(
                coordinator.audit_sink,
                *coordinator.current_sequence,
                timestamp,
                &coordinator.session_id,
                manifest,
                &proposal_hash,
                AuditOutcome::ExecutionFailed {
                    error: err.to_string(),
                },
                "Execution failure logging failed",
            );
            *coordinator.current_sequence += 1;

            match audit_result {
                Ok(_) => Err(err),
                Err(audit_err) => Err(BoundaryError::AuditSystemFailure(format!(
                    "Execution failed [{err}], AND logging failed [{audit_err}]"
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests;
