// SPDX-FileCopyrightText: Copyright (c) 2026 Hamster
// SPDX-License-Identifier: Apache-2.0

//! Opt-in real Kubernetes qualification; never targets a remote control plane.
use super::*;

#[tokio::test]
#[ignore = "requires a local billing-qualification cluster and exhausted fixture balance"]
async fn exhausted_billing_suspends_compute_and_retains_workspace() {
    assert_eq!(
        std::env::var("BILLING_RUNTIME_QUALIFICATION").as_deref(),
        Ok("1")
    );
    let billing_config: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("OPENSHELL_BILLING_CONFIG").unwrap()).unwrap(),
    )
    .unwrap();
    let endpoint = reqwest::Url::parse(billing_config["endpoint"].as_str().unwrap()).unwrap();
    assert!(matches!(
        endpoint.host_str(),
        Some("127.0.0.1" | "localhost" | "::1")
    ));
    assert!(
        billing_config["workspaces"]
            .as_object()
            .unwrap()
            .values()
            .all(|resource| resource
                .as_str()
                .is_some_and(|id| id.starts_with("billing-local-")))
    );
    let config = kube::Config::infer()
        .await
        .expect("local Kubernetes config");
    assert!(matches!(
        config.cluster_url.host(),
        Some("127.0.0.1" | "localhost" | "[::1]")
    ));
    let client = Client::try_from(config).expect("local Kubernetes client");
    let namespace = "billing-qualification";
    let mut driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig {
        namespace: namespace.into(),
        gateway_id: "billing-qualification".into(),
        ..Default::default()
    });
    driver.client = client.clone();
    driver.watch_client = client.clone();
    let api = driver
        .supported_sandbox_api_for_lookup(client.clone())
        .await
        .expect("installed Agent Sandbox controller");
    let before = api
        .api
        .get("billing-runtime")
        .await
        .expect("fixture Sandbox");
    let uid = before.metadata.uid.clone();
    assert_eq!(before.data["spec"]["operatingMode"], "Running");
    let pod_name = before
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(SANDBOX_POD_NAME_ANNOTATION))
        .cloned()
        .unwrap_or_else(|| "billing-runtime".into());
    let pods = Api::<Pod>::namespaced(client.clone(), namespace);
    assert!(pods.get_opt(&pod_name).await.unwrap().is_some());
    let claims = Api::<k8s_openapi::api::core::v1::PersistentVolumeClaim>::namespaced(
        client.clone(),
        namespace,
    );
    let claim_uid = claims.get("retained-data").await.unwrap().metadata.uid;
    let error = crate::billing::observe(client.clone(), &before)
        .await
        .unwrap_err();
    assert_eq!(error, "billing admission or receipt rejected");
    driver.reconcile_sandbox_runtime_resources().await;
    tokio::time::timeout(Duration::from_mins(1), async {
        loop {
            let current = api.api.get("billing-runtime").await.unwrap();
            if current.data["spec"]["operatingMode"] == "Suspended"
                && pods.get_opt(&pod_name).await.unwrap().is_none()
            {
                assert_eq!(current.metadata.uid, uid);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("controller confirmed compute release");
    driver.reconcile_sandbox_runtime_resources().await;
    assert_eq!(
        claims.get("retained-data").await.unwrap().metadata.uid,
        claim_uid
    );
}
