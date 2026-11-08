// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A claim left by an exited gateway process is settled only on driver proof.

use super::*;
use openshell_core::extension_protocol::COMPUTE_OPERATION_SETTLEMENT;

async fn stored(runtime: &ComputeRuntime, id: &str) -> Sandbox {
    runtime
        .store
        .get_message::<Sandbox>(id)
        .await
        .unwrap()
        .unwrap()
}

async fn settling_runtime(driver: Arc<ControlledDriver>) -> ComputeRuntime {
    let mut runtime = test_runtime(driver.clone()).await;
    runtime.operation_settlement_driver = Some(driver);
    runtime
        .driver_info
        .negotiated_extension
        .supported_capabilities
        .push(COMPUTE_OPERATION_SETTLEMENT.into());
    runtime
}

/// An Error sandbox whose start claim was never answered.
async fn pending_sandbox(runtime: &ComputeRuntime, operation_id: &str) -> Sandbox {
    let mut sandbox = error_sandbox_record("orphan-id", "orphan", "StartFailed");
    let mut operation = provisioning_deadline::new_record(openshell_core::time::now_ms());
    operation.driver_operation_pending = true;
    operation.driver_operation_id = operation_id.into();
    operation.cleanup_completed_time = openshell_core::time::timestamp_from_millis(320_000).ok();
    sandbox.status.as_mut().unwrap().provisioning = Some(operation);
    runtime.store.put_message(&sandbox).await.unwrap();
    sandbox
}

fn provisioning(sandbox: &Sandbox) -> &openshell_core::proto::SandboxProvisioning {
    sandbox
        .status
        .as_ref()
        .unwrap()
        .provisioning
        .as_ref()
        .unwrap()
}

#[tokio::test]
async fn startup_settles_a_claim_left_by_an_exited_process() {
    let driver = ControlledDriver::new();
    let runtime = settling_runtime(driver.clone()).await;
    let sandbox = pending_sandbox(&runtime, "previous-process").await;

    runtime
        .recover_persisted_lifecycle_transitions()
        .await
        .unwrap();

    let settled = stored(&runtime, sandbox.object_id()).await;
    let record = provisioning(&settled);
    assert!(!record.driver_operation_pending);
    // Kept so a delayed callback from that operation is still rejected.
    assert_eq!(record.driver_operation_id, "previous-process");
    // The operation may have created compute; cleanup must run again.
    assert!(record.cleanup_completed_time.is_none());
    assert_eq!(driver.settle_calls.load(Ordering::SeqCst), 1);

    // Stop is no longer blocked by the lost operation.
    let stopped = runtime.stop_sandbox("default", "orphan").await.unwrap();
    assert_eq!(stopped.phase(), SandboxPhase::Stopped as i32);
    assert_eq!(driver.stop_calls(), 1);
}

#[tokio::test]
async fn a_claim_this_process_owns_is_not_settled() {
    let driver = ControlledDriver::new();
    let runtime = settling_runtime(driver.clone()).await;
    let ownership = runtime.owned_operations.claim();
    let mut sandbox = pending_sandbox(&runtime, "unused").await;
    provisioning_operation::claim_record(&mut sandbox, &ownership);
    runtime.store.put_message(&sandbox).await.unwrap();
    let before = stored(&runtime, sandbox.object_id()).await;

    let settled = runtime
        .settle_orphaned_operation(&before, Duration::from_secs(5))
        .await
        .unwrap();

    assert!(settled.is_none());
    assert_eq!(stored(&runtime, sandbox.object_id()).await, before);
    assert_eq!(driver.settle_calls.load(Ordering::SeqCst), 0);

    // Once this process lets go, the same claim is recognisably orphaned.
    drop(ownership);
    assert!(
        runtime
            .settle_orphaned_operation(&before, Duration::from_secs(5))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_driver_without_settlement_keeps_the_claim() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    let sandbox = pending_sandbox(&runtime, "previous-process").await;
    let before = stored(&runtime, sandbox.object_id()).await;

    runtime
        .recover_persisted_lifecycle_transitions()
        .await
        .unwrap();

    assert_eq!(stored(&runtime, sandbox.object_id()).await, before);
    assert_eq!(driver.settle_calls.load(Ordering::SeqCst), 0);
    let error = runtime.stop_sandbox("default", "orphan").await.unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn an_unconfirmed_settlement_keeps_the_claim() {
    let driver = ControlledDriver::new();
    *driver.settle_error.lock().unwrap() = Some(Status::unavailable("driver restarting"));
    let runtime = settling_runtime(driver.clone()).await;
    let sandbox = pending_sandbox(&runtime, "previous-process").await;
    let before = stored(&runtime, sandbox.object_id()).await;

    let error = runtime
        .settle_orphaned_operation(&before, Duration::from_secs(5))
        .await
        .unwrap_err();

    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(stored(&runtime, sandbox.object_id()).await, before);
    assert_eq!(driver.stop_calls(), 0);
}
