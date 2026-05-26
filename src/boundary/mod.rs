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

struct PolicyEvaluation<'a> {
    invocation: &'a ValidatedToolInvocation,
    manifest: &'a ScopeManifest,
    session_id: &'a SessionId,
    current_time: u64,
    approval_proof: Option<&'a HumanApprovalProof>,
    verifier: &'a dyn ApprovalVerifier,
    state_store: &'a dyn ApprovalStateStore,
    policy: &'a BoundaryRuntimePolicy,
}

struct AuditEmission<'a> {
    sink: &'a dyn AuditSink,
    sequence: u64,
    timestamp: u64,
    session_id: &'a SessionId,
    manifest: &'a ScopeManifest,
    proposal_hash: &'a str,
    outcome: AuditOutcome,
    failure_context: &'a str,
}

struct PolicyGate;

impl PolicyGate {
    fn verify_and_reserve(
        evaluation: PolicyEvaluation<'_>,
    ) -> Result<ApprovalReservation, BoundaryError> {
        if evaluation.manifest.environment == Environment::Production
            && matches!(
                evaluation.invocation.capability(),
                ToolCapability::WriteFile | ToolCapability::ExecuteCargoTests
            )
        {
            let proof = evaluation.approval_proof.ok_or_else(|| {
                BoundaryError::PolicyDenial(
                    "Production mutations require explicit authorization signatures".into(),
                )
            })?;

            let canonical_manifest_hash = evaluation.manifest.compute_canonical_hash()?;

            let verification_context = crate::boundary::approval::ApprovalVerificationContext {
                session_id: evaluation.session_id,
                manifest_hash: &canonical_manifest_hash,
                invocation_hash: evaluation.invocation.invocation_hash(),
                capability: evaluation.invocation.capability(),
                current_time: evaluation.current_time,
            };

            evaluation
                .verifier
                .verify_approval(proof, &verification_context)?;
            evaluation
                .state_store
                .is_ticket_active(&proof.ticket_reference)?;
            evaluation.state_store.reserve_approval(
                &proof.approval_id,
                evaluation.policy.approval_reservation_ttl_secs,
            )?;

            return Ok(ApprovalReservation::Reserved {
                approval_id: proof.approval_id.clone(),
            });
        }

        Ok(ApprovalReservation::NotRequired)
    }
}

fn emit_audit(emission: AuditEmission<'_>) -> Result<(), BoundaryError> {
    emission
        .sink
        .emit_record(AuditRecord {
            event_id: uuid::Uuid::new_v4().to_string(),
            sequence_number: emission.sequence,
            timestamp: emission.timestamp,
            session_id: emission.session_id.clone(),
            manifest_id: emission.manifest.manifest_id.clone(),
            raw_proposal_hash: emission.proposal_hash.to_string(),
            outcome: emission.outcome,
        })
        .map_err(|audit_err| {
            BoundaryError::AuditSystemFailure(format!(
                "{}: {}",
                emission.failure_context, audit_err
            ))
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

        emit_audit(AuditEmission {
            sink: coordinator.audit_sink,
            sequence: *coordinator.current_sequence,
            timestamp,
            session_id: &coordinator.session_id,
            manifest,
            proposal_hash: &proposal_hash,
            outcome: AuditOutcome::PolicyDenied {
                reason: err.to_string(),
            },
            failure_context: "Terminal budget denial logging failed",
        })?;

        *coordinator.current_sequence += 1;
        return Err(err);
    }

    *coordinator.remaining_step_budget -= 1;

    let raw_proposal = match RawOutputParser::parse(raw_payload) {
        Ok(prop) => prop,
        Err(e) => {
            emit_audit(AuditEmission {
                sink: coordinator.audit_sink,
                sequence: *coordinator.current_sequence,
                timestamp,
                session_id: &coordinator.session_id,
                manifest,
                proposal_hash: &proposal_hash,
                outcome: AuditOutcome::ParseDenied {
                    reason: e.to_string(),
                },
                failure_context: "Terminal parse denial logging failed",
            })?;

            *coordinator.current_sequence += 1;
            return Err(e);
        }
    };

    let proposed_capability = raw_proposal.proposed_capability();

    let invocation = match ValidatedToolInvocation::try_from_proposal(raw_proposal, manifest) {
        Ok(inv) => inv,
        Err(e) => {
            emit_audit(AuditEmission {
                sink: coordinator.audit_sink,
                sequence: *coordinator.current_sequence,
                timestamp,
                session_id: &coordinator.session_id,
                manifest,
                proposal_hash: &proposal_hash,
                outcome: AuditOutcome::ValidationDenied {
                    proposed_capability,
                    reason: e.to_string(),
                },
                failure_context: "Terminal validation denial logging failed",
            })?;

            *coordinator.current_sequence += 1;
            return Err(e);
        }
    };

    let reservation = match PolicyGate::verify_and_reserve(PolicyEvaluation {
        invocation: &invocation,
        manifest,
        session_id: &coordinator.session_id,
        current_time: timestamp,
        approval_proof: approval,
        verifier: coordinator.verifier,
        state_store: coordinator.state_store,
        policy: coordinator.policy,
    }) {
        Ok(res) => res,
        Err(e) => {
            emit_audit(AuditEmission {
                sink: coordinator.audit_sink,
                sequence: *coordinator.current_sequence,
                timestamp,
                session_id: &coordinator.session_id,
                manifest,
                proposal_hash: &proposal_hash,
                outcome: AuditOutcome::PolicyDenied {
                    reason: e.to_string(),
                },
                failure_context: "Terminal policy denial logging failed",
            })?;

            *coordinator.current_sequence += 1;
            return Err(e);
        }
    };

    if let Err(audit_err) = emit_audit(AuditEmission {
        sink: coordinator.audit_sink,
        sequence: *coordinator.current_sequence,
        timestamp,
        session_id: &coordinator.session_id,
        manifest,
        proposal_hash: &proposal_hash,
        outcome: AuditOutcome::ExecutionStarted {
            capability: proposed_capability,
        },
        failure_context: "Pre-execution audit logging failed",
    }) {
        if let ApprovalReservation::Reserved { approval_id } = &reservation {
            let _ = coordinator.state_store.release_reserved_approval(approval_id);
        }

        return Err(audit_err);
    }

    *coordinator.current_sequence += 1;

    if let ApprovalReservation::Reserved { approval_id } = reservation {
        if let Err(e) = coordinator
            .state_store
            .consume_reserved_approval(&approval_id)
        {
            emit_audit(AuditEmission {
                sink: coordinator.audit_sink,
                sequence: *coordinator.current_sequence,
                timestamp,
                session_id: &coordinator.session_id,
                manifest,
                proposal_hash: &proposal_hash,
                outcome: AuditOutcome::ApprovalConsumptionFailed {
                    reason: e.to_string(),
                },
                failure_context: "Failed to log consumption failure",
            })?;

            *coordinator.current_sequence += 1;
            return Err(e);
        }
    }

    match coordinator.executor.execute(invocation).await {
        Ok(output_message) => {
            emit_audit(AuditEmission {
                sink: coordinator.audit_sink,
                sequence: *coordinator.current_sequence,
                timestamp,
                session_id: &coordinator.session_id,
                manifest,
                proposal_hash: &proposal_hash,
                outcome: AuditOutcome::ExecutionSucceeded {
                    capability: proposed_capability,
                },
                failure_context: "Execution succeeded, but completion audit failed",
            })?;

            *coordinator.current_sequence += 1;
            Ok(output_message)
        }
        Err(err) => {
            let audit_result = emit_audit(AuditEmission {
                sink: coordinator.audit_sink,
                sequence: *coordinator.current_sequence,
                timestamp,
                session_id: &coordinator.session_id,
                manifest,
                proposal_hash: &proposal_hash,
                outcome: AuditOutcome::ExecutionFailed {
                    error: err.to_string(),
                },
                failure_context: "Execution failure logging failed",
            });

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
