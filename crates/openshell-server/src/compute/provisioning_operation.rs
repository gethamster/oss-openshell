// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Retain ownership of submitted driver work until its outcome is known.
//!
//! Local cancellation and backend absence cannot prove that an external create
//! stopped. A durable claim prevents another replica from declaring cleanup
//! complete, retrying, or deleting the only record of an unresolved request.

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_core::{ObjectId, ObjectName, proto::Sandbox};
use tonic::Status;
use tracing::Instrument as _;

use super::{
    ComputeRuntime, provisioning_deadline, sandbox_provisioning_attempt_id,
    sandbox_resource_version, sandbox_runtime_generation,
};
use crate::persistence::PersistenceError;

/// An attempt may contain several recovery operations on the same generation.
/// Keep the last operation ID after settlement so a delayed callback cannot
/// adopt a newer operation merely because it has already finished.
pub(super) fn same_operation(left: &Sandbox, right: &Sandbox) -> bool {
    sandbox_provisioning_attempt_id(left) == sandbox_provisioning_attempt_id(right)
        && operation_id(left) == operation_id(right)
}

fn operation_id(sandbox: &Sandbox) -> Option<&str> {
    sandbox
        .status
        .as_ref()?
        .provisioning
        .as_ref()
        .map(|record| record.driver_operation_id.as_str())
}

/// Driver operations this gateway process has claimed and not yet settled.
///
/// A durable claim outlives the process that made it. Every claim is
/// registered here before it is written and removed only once its worker has
/// settled it, so a pending claim missing from this set was made by a process
/// that has exited. On a single-replica store no other process can own it.
#[derive(Debug, Default)]
pub(super) struct OwnedOperations(Mutex<HashSet<String>>);

impl OwnedOperations {
    pub(super) fn claim(self: &Arc<Self>) -> OwnedOperation {
        let id = uuid::Uuid::new_v4().to_string();
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.clone());
        OwnedOperation {
            registry: self.clone(),
            id,
        }
    }

    pub(super) fn owns(&self, id: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(id)
    }
}

/// This process's ownership of one claim, released when dropped.
#[derive(Debug)]
pub(super) struct OwnedOperation {
    registry: Arc<OwnedOperations>,
    id: String,
}

impl Drop for OwnedOperation {
    fn drop(&mut self) {
        self.registry
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

/// Called only inside a CAS that has checked the prior operation is settled.
/// Legacy rows without an attempt retain their existing lifecycle contract.
pub(super) fn claim_record(sandbox: &mut Sandbox, ownership: &OwnedOperation) {
    if let Some(record) = sandbox
        .status
        .as_mut()
        .and_then(|status| status.provisioning.as_mut())
    {
        record.driver_operation_pending = true;
        record.driver_operation_id.clone_from(&ownership.id);
    }
}

pub(super) fn ensure_current_result(current: &Sandbox, owned: &Sandbox) -> Result<(), Status> {
    if !same_operation(current, owned)
        || sandbox_runtime_generation(current) != sandbox_runtime_generation(owned)
    {
        return Err(Status::aborted(
            "sandbox driver operation changed before result handling",
        ));
    }
    if provisioning_deadline::timed_out(current) {
        return Err(Status::deadline_exceeded("provisioning deadline expired"));
    }
    ensure_operation_settled(current)
}

pub(super) fn ensure_operation_settled(sandbox: &Sandbox) -> Result<(), Status> {
    if provisioning_deadline::driver_operation_pending(sandbox) {
        return Err(Status::failed_precondition(
            "previous driver operation is still pending; retry and deletion are blocked",
        ));
    }
    Ok(())
}

/// Keep monitor interruption separate from an actual driver response. Only
/// the latter may enter the caller's existing failure recovery path.
#[derive(Debug, thiserror::Error)]
pub(super) enum ProvisioningOperationError {
    #[error("{status}")]
    Driver {
        status: Status,
        settled: Box<Sandbox>,
    },
    #[error("{0}")]
    Monitor(Status),
    #[error("{0}")]
    Unsettled(Status),
}

impl From<ProvisioningOperationError> for Status {
    fn from(error: ProvisioningOperationError) -> Self {
        match error {
            ProvisioningOperationError::Driver { status, .. }
            | ProvisioningOperationError::Monitor(status)
            | ProvisioningOperationError::Unsettled(status) => status,
        }
    }
}

impl ComputeRuntime {
    /// Claim before polling the operation, then retain its task even when the
    /// caller or deadline monitor leaves. Pending describes the owned future,
    /// not backend cancellation: transport-error ambiguity remains governed by
    /// the compute driver's existing error contract.
    pub(super) async fn await_provisioning_operation<T: Send + 'static>(
        &self,
        starting: &Sandbox,
        operation: impl Future<Output = Result<T, Status>> + Send + 'static,
    ) -> Result<(T, Box<Sandbox>), ProvisioningOperationError> {
        let ownership = self.owned_operations.claim();
        let claimed = self
            .claim_provisioning_operation(starting, &ownership)
            .await
            .map_err(ProvisioningOperationError::Monitor)?;
        self.await_claimed_provisioning_operation(&claimed, ownership, operation)
            .await
    }

    /// The caller has atomically claimed both its lifecycle transition and the
    /// operation. The detached worker owns I/O, not the caller's local gate.
    pub(super) async fn await_claimed_provisioning_operation<T: Send + 'static>(
        &self,
        starting: &Sandbox,
        ownership: OwnedOperation,
        operation: impl Future<Output = Result<T, Status>> + Send + 'static,
    ) -> Result<(T, Box<Sandbox>), ProvisioningOperationError> {
        let tracked = sandbox_provisioning_attempt_id(starting).is_some();
        let runtime = self.clone();
        let owned_attempt = starting.clone();
        // Dropping a JoinHandle detaches its task. Do not abort it on a monitor
        // error or deadline: the remote side may still commit the request.
        let worker = async move {
            // Ownership ends with this task, after settlement is persisted or
            // abandoned; an orphaned claim is then recognisable as one.
            let _ownership = ownership;
            let result = operation.await;
            let settled = if tracked {
                let settled = runtime
                    .settle_provisioning_operation(&owned_attempt)
                    .await
                    .map_err(ProvisioningOperationError::Monitor)?;
                // Settlement records a known response even if another writer
                // rotated identity. That response cannot bind or compensate
                // against the replacement generation in its returned snapshot.
                if sandbox_runtime_generation(&settled)
                    != sandbox_runtime_generation(&owned_attempt)
                {
                    return Err(ProvisioningOperationError::Monitor(Status::aborted(
                        "sandbox runtime generation changed during driver operation",
                    )));
                }
                settled
            } else {
                owned_attempt
            };
            match result {
                Ok(response) => Ok((response, Box::new(settled))),
                Err(status) => Err(ProvisioningOperationError::Driver {
                    status,
                    settled: Box::new(settled),
                }),
            }
        };
        // Retain the request span so detaching ownership preserves the driver
        // call's parent trace, including when the caller stops waiting.
        let mut worker = tokio::spawn(worker.in_current_span());
        loop {
            tokio::select! {
                result = &mut worker => return result.map_err(|error| {
                    ProvisioningOperationError::Unsettled(Status::internal(format!(
                        "driver operation owner terminated; outcome remains unknown: {error}"
                    )))
                })?,
                () = tokio::time::sleep(Duration::from_secs(1)) => {
                    let current = self.store.get_message::<Sandbox>(starting.object_id())
                        .await.map_err(|error| ProvisioningOperationError::Monitor(
                            Status::internal(format!("monitor provisioning: {error}"))
                        ))?
                        .ok_or_else(|| ProvisioningOperationError::Monitor(
                            Status::not_found("sandbox removed during startup")
                        ))?;
                    if !same_operation(&current, starting)
                        || sandbox_runtime_generation(&current) != sandbox_runtime_generation(starting) {
                        return Err(ProvisioningOperationError::Monitor(Status::aborted(
                            "sandbox provisioning attempt changed while waiting for compute"
                        )));
                    }
                    if provisioning_deadline::timed_out(&current) {
                        return Err(ProvisioningOperationError::Monitor(Status::deadline_exceeded(
                            "provisioning deadline expired; driver settlement may still be pending"
                        )));
                    }
                }
            }
        }
    }

    async fn claim_provisioning_operation(
        &self,
        starting: &Sandbox,
        ownership: &OwnedOperation,
    ) -> Result<Sandbox, Status> {
        let Some(attempt_id) = sandbox_provisioning_attempt_id(starting) else {
            // Legacy rows without an attempt do not gain a synthetic deadline.
            return Ok(starting.clone());
        };
        if attempt_id.is_empty() {
            return Err(Status::failed_precondition("provisioning attempt is empty"));
        }
        for _ in 0..super::START_PHASE_CAS_RETRY_LIMIT {
            let current = self
                .store
                .get_message::<Sandbox>(starting.object_id())
                .await
                .map_err(|error| Status::internal(error.to_string()))?
                .ok_or_else(|| Status::not_found("sandbox removed before driver dispatch"))?;
            if provisioning_deadline::timed_out(&current) {
                return Err(Status::deadline_exceeded(
                    "provisioning deadline already expired",
                ));
            }
            if provisioning_deadline::driver_operation_pending(&current) {
                return Err(Status::failed_precondition(
                    "previous driver operation may still complete; retry and deletion are blocked",
                ));
            }
            if !same_operation(&current, starting)
                || sandbox_runtime_generation(&current) != sandbox_runtime_generation(starting)
            {
                return Err(Status::aborted(
                    "provisioning operation changed before driver dispatch",
                ));
            }
            if current.phase() != starting.phase() {
                return Err(Status::aborted(
                    "sandbox phase changed before driver dispatch",
                ));
            }
            match self
                .store
                .update_message_cas::<Sandbox, _>(
                    starting.object_id(),
                    sandbox_resource_version(&current),
                    |sandbox| claim_record(sandbox, ownership),
                )
                .await
            {
                Ok(updated) => {
                    self.sandbox_index.update_from_sandbox(&updated);
                    self.sandbox_watch_bus.notify(starting.object_id());
                    return Ok(updated);
                }
                Err(PersistenceError::Conflict { .. }) => {}
                Err(error) => return Err(Status::internal(error.to_string())),
            }
        }
        Err(Status::aborted(
            "sandbox kept changing before driver dispatch",
        ))
    }

    async fn settle_provisioning_operation(&self, starting: &Sandbox) -> Result<Sandbox, Status> {
        // Keep the observed response in this task across transient persistence
        // failures. A process crash still leaves the durable claim intact;
        // neither lease expiry nor backend absence can safely clear it.
        loop {
            let result = self.try_settle_provisioning_operation(starting).await;
            match result {
                Ok(settled) => return Ok(settled),
                Err(error) if error.code() == tonic::Code::Aborted => return Err(error),
                Err(error) => {
                    tracing::warn!(sandbox_id = starting.object_id(), %error,
                        "Retaining driver response until operation ownership can be persisted");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn try_settle_provisioning_operation(
        &self,
        starting: &Sandbox,
    ) -> Result<Sandbox, Status> {
        let current = self
            .store
            .get_message::<Sandbox>(starting.object_id())
            .await
            .map_err(|error| Status::internal(error.to_string()))?
            .ok_or_else(|| Status::aborted("sandbox removed before driver settlement"))?;
        if !same_operation(&current, starting) {
            return Err(Status::aborted(
                "provisioning attempt changed before driver settlement",
            ));
        }
        let updated = self
            .store
            .update_message_cas::<Sandbox, _>(
                starting.object_id(),
                sandbox_resource_version(&current),
                |sandbox| {
                    if let Some(record) = sandbox
                        .status
                        .as_mut()
                        .and_then(|status| status.provisioning.as_mut())
                    {
                        record.driver_operation_pending = false;
                        // Any stop before this response may have seen absence before
                        // the late create committed. Require another cleanup pass.
                        record.cleanup_completed_time = None;
                        // The retry timestamp may be another replica's active
                        // STOP lease. Preserve it through driver settlement.
                    }
                },
            )
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        self.sandbox_index.update_from_sandbox(&updated);
        self.sandbox_watch_bus.notify(starting.object_id());
        Ok(updated)
    }
}

/// How long startup recovery waits for the driver before handing an orphaned
/// claim to a background retry, so one busy sandbox cannot hold up the rest.
const STARTUP_SETTLEMENT_WAIT: Duration = Duration::from_mins(1);
/// A driver finishing a long create (an image pull) may take many minutes.
const BACKGROUND_SETTLEMENT_WAIT: Duration = Duration::from_mins(15);
const BACKGROUND_SETTLEMENT_RETRY: Duration = Duration::from_secs(30);

impl ComputeRuntime {
    /// Whether this gateway can prove a claim orphaned and its operation over:
    /// it is the store's only writer and the driver negotiated settlement.
    fn settles_orphaned_operations(&self) -> bool {
        self.store.is_single_replica()
            && self.operation_settlement_driver.is_some()
            && self
                .driver_info
                .negotiated_extension
                .supported_capabilities
                .iter()
                .any(|capability| {
                    capability == openshell_core::extension_protocol::COMPUTE_OPERATION_SETTLEMENT
                })
    }

    /// The pending claim's operation ID when no live process owns it.
    async fn orphaned_operation(&self, sandbox: &Sandbox) -> Result<Option<String>, Status> {
        if !provisioning_deadline::driver_operation_pending(sandbox)
            || !self.settles_orphaned_operations()
        {
            return Ok(None);
        }
        let Some(id) = operation_id(sandbox).map(str::to_owned) else {
            return Ok(None);
        };
        if self.owned_operations.owns(&id) {
            return Ok(None);
        }
        // An image update keeps its claim under a durable intent that its own
        // recovery resumes and completes; that claim is not orphaned.
        let image_state = self
            .store
            .get_sandbox_image_state(sandbox.object_id())
            .await
            .map_err(|error| Status::internal(format!("read sandbox image state: {error}")))?;
        if image_state
            .and_then(|state| state.pending)
            .is_some_and(|intent| intent.operation_id == id)
        {
            return Ok(None);
        }
        Ok(Some(id))
    }

    /// Release a claim left by a gateway process that exited mid-call.
    ///
    /// Neither time nor backend absence shows that the exited process's driver
    /// call stopped; only the driver knows. Once it confirms that no operation
    /// it accepted for the sandbox can still change resources, the claim
    /// protects nothing. Settlement then matches a known response: cleanup must
    /// run again, and stop, start and delete are no longer blocked.
    ///
    /// Returns the settled record, or `None` when the claim is not orphaned.
    pub(super) async fn settle_orphaned_operation(
        &self,
        sandbox: &Sandbox,
        wait: Duration,
    ) -> Result<Option<Sandbox>, Status> {
        let Some(orphaned_id) = self.orphaned_operation(sandbox).await? else {
            return Ok(None);
        };
        let driver = self.operation_settlement_driver.clone().ok_or_else(|| {
            Status::unimplemented("compute driver has no registered operation settlement")
        })?;
        let request = openshell_core::proto::compute::v1::SettleSandboxOperationsRequest {
            sandbox_id: sandbox.object_id().to_string(),
            name: sandbox.object_name().to_string(),
        };
        tokio::time::timeout(
            wait,
            self.driver.call_owned(
                openshell_otel::rpc::SETTLE_SANDBOX_OPERATIONS,
                Some(sandbox.object_id()),
                move |_| async move {
                    driver
                        .settle_sandbox_operations(tonic::Request::new(request))
                        .await
                },
            ),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("driver is still finishing the operation"))??;

        for _ in 0..super::START_PHASE_CAS_RETRY_LIMIT {
            let current = self
                .store
                .get_message::<Sandbox>(sandbox.object_id())
                .await
                .map_err(|error| Status::internal(error.to_string()))?
                .ok_or_else(|| Status::not_found("sandbox removed during settlement"))?;
            if !provisioning_deadline::driver_operation_pending(&current)
                || operation_id(&current) != Some(orphaned_id.as_str())
            {
                return Ok(Some(current));
            }
            match self
                .store
                .update_message_cas::<Sandbox, _>(
                    sandbox.object_id(),
                    sandbox_resource_version(&current),
                    |sandbox| {
                        if let Some(record) = sandbox
                            .status
                            .as_mut()
                            .and_then(|status| status.provisioning.as_mut())
                        {
                            record.driver_operation_pending = false;
                            // The operation may have created compute after an
                            // earlier stop saw none; require another cleanup.
                            record.cleanup_completed_time = None;
                        }
                    },
                )
                .await
            {
                Ok(updated) => {
                    self.sandbox_index.update_from_sandbox(&updated);
                    self.sandbox_watch_bus.notify(sandbox.object_id());
                    tracing::info!(
                        sandbox_id = sandbox.object_id(),
                        driver_operation_id = orphaned_id,
                        "Settled driver operation left by an exited gateway process"
                    );
                    return Ok(Some(updated));
                }
                Err(PersistenceError::Conflict { .. }) => {}
                Err(error) => return Err(Status::internal(error.to_string())),
            }
        }
        Err(Status::aborted("sandbox kept changing during settlement"))
    }

    /// Startup recovery: settle an orphaned claim now when the driver answers
    /// promptly, otherwise keep retrying in the background so the sandbox
    /// leaves the blocked state as soon as its operation finishes.
    pub(super) async fn settle_orphaned_operation_at_startup(&self, sandbox: Sandbox) -> Sandbox {
        match self
            .settle_orphaned_operation(&sandbox, STARTUP_SETTLEMENT_WAIT)
            .await
        {
            Ok(Some(settled)) => settled,
            Ok(None) => sandbox,
            Err(error) => {
                tracing::warn!(sandbox_id = sandbox.object_id(), %error,
                    "Orphaned driver operation is not settled yet; retrying in the background");
                let runtime = self.clone();
                let retry = sandbox.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(BACKGROUND_SETTLEMENT_RETRY).await;
                        let current = match runtime
                            .store
                            .get_message::<Sandbox>(retry.object_id())
                            .await
                        {
                            Ok(Some(current)) => current,
                            Ok(None) => return,
                            Err(error) => {
                                tracing::warn!(sandbox_id = retry.object_id(), %error,
                                    "Failed to re-read sandbox for operation settlement");
                                continue;
                            }
                        };
                        match runtime
                            .settle_orphaned_operation(&current, BACKGROUND_SETTLEMENT_WAIT)
                            .await
                        {
                            Ok(_) => return,
                            Err(error) => tracing::warn!(sandbox_id = retry.object_id(), %error,
                                "Orphaned driver operation is not settled yet"),
                        }
                    }
                });
                sandbox
            }
        }
    }
}
