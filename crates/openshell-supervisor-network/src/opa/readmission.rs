// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Re-admission of established tunnels after a policy reload.
//!
//! A policy reload advances the generation and makes every pinned tunnel
//! stale. A reload that does not change what a tunnel was admitted with (for
//! example, one that only adds rules for other hosts) must not cut that
//! tunnel. A stale tunnel is therefore checked again with the same
//! authorization that admitted it, against the current policy. The tunnel
//! continues under the current generation only when that authorization
//! allows it with identical connect-time state. Any difference, denial or
//! error closes the tunnel, as before.

use super::{
    EgressAuthorization, MatchedEndpoint, NetworkAction, NetworkInput, OpaEngine,
    PolicyGenerationGuard, TunnelPolicyEngine,
};
use miette::Result;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::debug;

/// Connect-time authorization state of an established tunnel.
///
/// The relay keeps state derived from these values for the tunnel lifetime:
/// L7 route and rules, TLS mode, credential guard, destination plan and the
/// already validated upstream address. The current policy must reproduce all
/// of them exactly, or the tunnel cannot continue.
#[derive(Debug, Clone)]
pub struct TunnelAdmission {
    /// The exact L4 input that admitted the tunnel, including the binary
    /// digest. Identity is never resolved again.
    input: NetworkInput,
    matched_policy: Option<String>,
    endpoint_configs: Vec<regorus::Value>,
    matched_endpoints: Vec<MatchedEndpoint>,
    exact_declared_endpoint_host: bool,
}

impl TunnelAdmission {
    /// Capture the admission of an allowed tunnel. Returns `None` for a
    /// denied action, which cannot be re-admitted.
    pub fn new(
        input: NetworkInput,
        action: &NetworkAction,
        endpoint_configs: Vec<regorus::Value>,
        matched_endpoints: Vec<MatchedEndpoint>,
        exact_declared_endpoint_host: bool,
    ) -> Option<Self> {
        let NetworkAction::Allow { matched_policy } = action else {
            return None;
        };
        Some(Self {
            input,
            matched_policy: matched_policy.clone(),
            endpoint_configs,
            matched_endpoints,
            exact_declared_endpoint_host,
        })
    }

    fn admits(&self, authorization: &EgressAuthorization) -> bool {
        matches!(
            &authorization.action,
            NetworkAction::Allow { matched_policy } if *matched_policy == self.matched_policy
        ) && same_endpoints(&authorization.endpoint_configs, &self.endpoint_configs)
            && authorization.matched_endpoints.len() == self.matched_endpoints.len()
            && authorization
                .matched_endpoints
                .iter()
                .zip(&self.matched_endpoints)
                .all(|(current, admitted)| {
                    current.policy_name == admitted.policy_name
                        && current.endpoint_index == admitted.endpoint_index
                        && same_endpoint(&current.endpoint, &admitted.endpoint)
                })
            && authorization.exact_declared_endpoint_host == self.exact_declared_endpoint_host
    }
}

fn same_endpoints(current: &[regorus::Value], admitted: &[regorus::Value]) -> bool {
    current.len() == admitted.len()
        && current
            .iter()
            .zip(admitted)
            .all(|(current, admitted)| same_endpoint(current, admitted))
}

/// Compare endpoint data across generations.
///
/// Policy conversion stamps the hash of the complete policy into every
/// inspected endpoint, so the hash changes on every reload even when the
/// endpoint itself does not. It is ignored for comparison, except on an
/// endpoint with an `endpoint_id`: MCP status reports are keyed by that hash,
/// so those tunnels must still close.
fn same_endpoint(current: &regorus::Value, admitted: &regorus::Value) -> bool {
    if current == admitted {
        return true;
    }
    match (without_policy_hash(current), without_policy_hash(admitted)) {
        (Some(current), Some(admitted)) => current == admitted,
        _ => false,
    }
}

fn without_policy_hash(endpoint: &regorus::Value) -> Option<regorus::Value> {
    let fields = endpoint.as_object().ok()?;
    if fields.contains_key(&regorus::Value::from("endpoint_id")) {
        return None;
    }
    let mut fields = fields.clone();
    fields.remove(&regorus::Value::from("policy_hash"))?;
    Some(regorus::Value::from(fields))
}

/// Re-admission handle shared by a tunnel's evaluator and generation guards.
pub struct TunnelReadmission {
    engine: Arc<OpaEngine>,
    admission: TunnelAdmission,
}

impl std::fmt::Debug for TunnelReadmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelReadmission")
            .field("admission", &self.admission)
            .finish_non_exhaustive()
    }
}

impl TunnelReadmission {
    pub fn new(engine: Arc<OpaEngine>, admission: TunnelAdmission) -> Arc<Self> {
        Arc::new(Self { engine, admission })
    }

    /// Evaluate the original admission against the current policy.
    ///
    /// Returns the generation of that evaluation when it allows the tunnel
    /// with identical connect-time state, and `None` otherwise. A fail-closed
    /// quarantine denies in `authorize_egress`, so it is never re-admitted.
    pub(crate) fn admitting_generation(&self) -> Result<Option<u64>> {
        let authorization = self.engine.authorize_egress(&self.admission.input)?;
        Ok(self
            .admission
            .admits(&authorization)
            .then_some(authorization.generation))
    }

    /// Pin a new generation guard at the current generation, if the current
    /// policy re-admits the tunnel.
    pub fn pin_guard(self: &Arc<Self>) -> Result<Option<PolicyGenerationGuard>> {
        let Some(generation) = self.admitting_generation()? else {
            return Ok(None);
        };
        let guard = self.engine.generation_guard(generation)?;
        Ok(Some(guard.with_readmission(Arc::clone(self))))
    }

    /// Clone a tunnel evaluator at the current generation, if the current
    /// policy re-admits the tunnel.
    pub fn pin_tunnel(self: &Arc<Self>) -> Result<Option<TunnelPolicyEngine>> {
        let Some(generation) = self.admitting_generation()? else {
            return Ok(None);
        };
        let tunnel = self.engine.clone_engine_for_tunnel(generation)?;
        Ok(Some(tunnel.with_readmission(Arc::clone(self))))
    }
}

impl PolicyGenerationGuard {
    /// Attach re-admission state so a stale guard can be checked again.
    #[must_use]
    pub fn with_readmission(mut self, readmission: Arc<TunnelReadmission>) -> Self {
        self.readmission = Some(readmission);
        self
    }

    /// Stop re-admission for this guard's tunnel.
    ///
    /// An upgraded or raw stream has no request boundary at which a reloaded
    /// policy can be applied. After this call, every clone of the guard (and
    /// the tunnel evaluator that owns it) fails closed on the next reload, as
    /// a guard without re-admission state does.
    pub fn end_readmission(&self) {
        self.readmission_ended.store(true, Ordering::Release);
    }

    fn readmission(&self) -> Option<&Arc<TunnelReadmission>> {
        if self.readmission_ended.load(Ordering::Acquire) {
            return None;
        }
        self.readmission.as_ref()
    }

    /// Make a stale stand-alone guard current again if the current policy
    /// re-admits its tunnel.
    ///
    /// Returns `true` when the guard is current on return. Returns `false`
    /// when the guard is stale and cannot be re-admitted; the caller must
    /// close. A guard owned by a `TunnelPolicyEngine` is never moved here,
    /// because its evaluator must move with it.
    pub fn readmit_if_stale(&self) -> bool {
        if !self.is_stale() {
            return true;
        }
        if self.engine_bound {
            return false;
        }
        let Some(readmission) = self.readmission() else {
            return false;
        };
        let generation = match readmission.admitting_generation() {
            Ok(Some(generation)) => generation,
            Ok(None) => return false,
            Err(error) => {
                debug!(error = %error, "tunnel re-admission failed");
                return false;
            }
        };
        // Publish the new generation only while it is still current, so a
        // further reload cannot be skipped.
        match readmission
            .engine
            .with_current_generation(generation, |generation| {
                self.captured_generation
                    .store(generation, Ordering::Release);
            }) {
            Ok(Some(())) => true,
            Ok(None) => false,
            Err(error) => {
                debug!(error = %error, "tunnel re-admission failed");
                false
            }
        }
    }

    /// Wait until a policy reload revokes this guard's tunnel.
    ///
    /// Without re-admission state this is `wait_until_stale`. With it, each
    /// new generation is checked against the tunnel's admission. A generation
    /// that still admits the tunnel does not end the wait. The guard itself
    /// does not move: request boundaries re-admit the tunnel before they use
    /// the new generation, and in-flight checks stay fail-closed.
    pub async fn wait_until_revoked(&self) {
        let mut receiver = self.generation_rx.clone();
        let mut checked = self.captured_generation();
        loop {
            let current = self.current_generation();
            if current != checked && current != self.captured_generation() {
                // Checked on each change, so a stream that ends re-admission
                // after it started closes on the next reload.
                let Some(readmission) = self.readmission() else {
                    return;
                };
                match readmission.admitting_generation() {
                    Ok(Some(generation)) => checked = generation,
                    Ok(None) => return,
                    Err(error) => {
                        debug!(error = %error, "tunnel re-admission failed");
                        return;
                    }
                }
                continue;
            }
            checked = current;
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

impl TunnelPolicyEngine {
    /// Attach re-admission state so a stale tunnel can be checked again.
    #[must_use]
    pub fn with_readmission(mut self, readmission: Arc<TunnelReadmission>) -> Self {
        self.generation_guard.readmission = Some(readmission);
        self
    }

    /// Move a stale tunnel to the current generation if the current policy
    /// re-admits it.
    ///
    /// On success the cloned policy, the middleware runner and the captured
    /// generation are replaced together, so later requests are evaluated
    /// only against the current policy. Returns `false` when the tunnel is
    /// stale and cannot be re-admitted; the caller must close.
    pub fn readmit_if_stale(&self) -> bool {
        if !self.is_stale() {
            return true;
        }
        let Some(readmission) = self.generation_guard.readmission() else {
            return false;
        };
        match self.readmit(readmission) {
            Ok(readmitted) => readmitted,
            Err(error) => {
                debug!(error = %error, "tunnel re-admission failed");
                false
            }
        }
    }

    fn readmit(&self, readmission: &TunnelReadmission) -> Result<bool> {
        let Some(generation) = readmission.admitting_generation()? else {
            return Ok(false);
        };
        // Fails when another reload happened after the admission check.
        let fresh = readmission.engine.clone_engine_for_tunnel(generation)?;
        let fresh_engine = fresh
            .engine
            .into_inner()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;
        let fresh_runner = fresh
            .middleware_runner
            .into_inner()
            .map_err(|_| miette::miette!("middleware runner lock poisoned"))?;
        let mut engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;
        let mut runner = self
            .middleware_runner
            .write()
            .map_err(|_| miette::miette!("middleware runner lock poisoned"))?;
        *engine = fresh_engine;
        *runner = fresh_runner;
        // Publish the generation last: a reader that sees it current also
        // sees the replaced policy and runner.
        self.generation_guard
            .captured_generation
            .store(generation, Ordering::Release);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const POLICY_REGO: &str = include_str!("../../data/sandbox-policy.rego");
    const REST_POLICY: &str = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/models"
    binaries:
      - { path: /usr/bin/curl }
"#;
    const UNRELATED_RULE_ADDED: &str = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/models"
    binaries:
      - { path: /usr/bin/curl }
  repository:
    name: repository
    endpoints:
      - host: github.example.test
        port: 443
    binaries:
      - { path: /usr/bin/git }
"#;
    const HOST_REMOVED: &str = r"
network_policies:
  repository:
    name: repository
    endpoints:
      - host: github.example.test
        port: 443
    binaries:
      - { path: /usr/bin/git }
";
    const BINARY_REMOVED: &str = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/models"
    binaries:
      - { path: /usr/bin/wget }
"#;
    const RULE_CHANGED: &str = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/other"
    binaries:
      - { path: /usr/bin/curl }
"#;

    fn input() -> NetworkInput {
        NetworkInput {
            host: "api.example.test".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        }
    }

    fn admitted_tunnel() -> (Arc<OpaEngine>, TunnelPolicyEngine) {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, REST_POLICY).unwrap());
        let authorization = engine.authorize_egress(&input()).unwrap();
        let admission = TunnelAdmission::new(
            input(),
            &authorization.action,
            authorization.endpoint_configs,
            authorization.matched_endpoints,
            authorization.exact_declared_endpoint_host,
        )
        .expect("allowed tunnel has an admission");
        let tunnel = engine
            .clone_engine_for_tunnel(authorization.generation)
            .unwrap()
            .with_readmission(TunnelReadmission::new(Arc::clone(&engine), admission));
        (engine, tunnel)
    }

    fn allows_models_request(tunnel: &TunnelPolicyEngine) -> bool {
        let mut engine = tunnel.engine().lock().unwrap();
        crate::opa::set_regorus_input(
            &mut engine,
            serde_json::json!({
                "network": { "host": "api.example.test", "port": 8080 },
                "exec": { "path": "/usr/bin/curl", "ancestors": [], "cmdline_paths": [] },
                "request": { "method": "GET", "path": "/models", "query_params": {} },
            }),
        )
        .unwrap();
        engine
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap()
            == regorus::Value::from(true)
    }

    #[test]
    fn stale_tunnel_is_recaptured_when_current_policy_still_admits_it() {
        let (engine, tunnel) = admitted_tunnel();
        let guard = tunnel.generation_guard().clone();
        engine.reload(POLICY_REGO, UNRELATED_RULE_ADDED).unwrap();
        assert!(tunnel.is_stale());

        assert!(tunnel.readmit_if_stale());
        assert_eq!(tunnel.captured_generation(), engine.current_generation());
        assert!(!guard.is_stale(), "guard clones move with the tunnel");
        assert!(allows_models_request(&tunnel));
        // The re-captured policy is the current one, not the admitted one:
        // it knows the rule that the reload added.
        let mut cloned = tunnel.engine().lock().unwrap();
        crate::opa::set_regorus_input(
            &mut cloned,
            serde_json::json!({
                "network": { "host": "github.example.test", "port": 443 },
                "exec": { "path": "/usr/bin/git", "ancestors": [], "cmdline_paths": [] },
            }),
        )
        .unwrap();
        assert_eq!(
            cloned
                .eval_rule("data.openshell.sandbox.allow_network".into())
                .unwrap(),
            regorus::Value::from(true)
        );
    }

    #[test]
    fn stale_tunnel_fails_closed_when_current_policy_changes_its_admission() {
        for (name, reloaded) in [
            ("host removed", HOST_REMOVED),
            ("binary removed", BINARY_REMOVED),
            ("L7 rule changed", RULE_CHANGED),
        ] {
            let (engine, tunnel) = admitted_tunnel();
            let admitted_generation = tunnel.captured_generation();
            engine.reload(POLICY_REGO, reloaded).unwrap();

            assert!(!tunnel.readmit_if_stale(), "{name}: must fail closed");
            assert!(tunnel.is_stale(), "{name}: tunnel must stay stale");
            assert_eq!(tunnel.captured_generation(), admitted_generation);
        }
    }

    fn proto_policy(yaml: &str) -> crate::opa::ProtoSandboxPolicy {
        let proto = openshell_policy::parse_sandbox_policy(&format!("version: 1\n{yaml}"))
            .expect("authored policy");
        openshell_policy::validate_and_canonicalize_sandbox_policy(proto)
            .expect("policy canonicalizes")
    }

    fn admitted_proto_tunnel(yaml: &str) -> (Arc<OpaEngine>, TunnelPolicyEngine) {
        let engine = Arc::new(OpaEngine::from_proto(&proto_policy(yaml)).unwrap());
        let authorization = engine.authorize_egress(&input()).unwrap();
        let admission = TunnelAdmission::new(
            input(),
            &authorization.action,
            authorization.endpoint_configs,
            authorization.matched_endpoints,
            authorization.exact_declared_endpoint_host,
        )
        .expect("allowed tunnel has an admission");
        let tunnel = engine
            .clone_engine_for_tunnel(authorization.generation)
            .unwrap()
            .with_readmission(TunnelReadmission::new(Arc::clone(&engine), admission));
        (engine, tunnel)
    }

    #[test]
    fn proto_reload_with_unrelated_rule_readmits_inspected_tunnel() {
        // The production path stamps the whole-policy hash into every
        // inspected endpoint, so the hash differs after any reload.
        let (engine, tunnel) = admitted_proto_tunnel(REST_POLICY);
        engine
            .reload_from_proto(&proto_policy(UNRELATED_RULE_ADDED))
            .unwrap();

        assert!(tunnel.readmit_if_stale());
        assert_eq!(tunnel.captured_generation(), engine.current_generation());
        assert!(allows_models_request(&tunnel));
    }

    #[test]
    fn proto_reload_that_changes_the_endpoint_closes_inspected_tunnel() {
        for (name, reloaded) in [
            ("host removed", HOST_REMOVED),
            ("binary removed", BINARY_REMOVED),
            ("L7 rule changed", RULE_CHANGED),
        ] {
            let (engine, tunnel) = admitted_proto_tunnel(REST_POLICY);
            engine.reload_from_proto(&proto_policy(reloaded)).unwrap();

            assert!(!tunnel.readmit_if_stale(), "{name}: must fail closed");
        }
    }

    #[test]
    fn proto_reload_closes_mcp_tunnel_whose_status_is_keyed_by_policy_hash() {
        let mcp_policy = REST_POLICY
            .replace("protocol: rest", "protocol: mcp")
            .replace(
                "          - allow:\n              method: GET\n              path: \"/models\"\n",
                "          - allow:\n              method: initialize\n",
            );
        let with_unrelated = format!(
            "{mcp_policy}{}",
            &UNRELATED_RULE_ADDED[UNRELATED_RULE_ADDED.find("  repository:").unwrap()..]
        );
        let (engine, tunnel) = admitted_proto_tunnel(&mcp_policy);
        engine
            .reload_from_proto(&proto_policy(&with_unrelated))
            .unwrap();

        assert!(!tunnel.readmit_if_stale());
    }

    #[test]
    fn stale_tunnel_fails_closed_under_quarantine() {
        let (engine, tunnel) = admitted_tunnel();
        engine.enter_fail_closed("candidate policy failed").unwrap();

        assert!(!tunnel.readmit_if_stale());
    }

    #[test]
    fn stale_tunnel_without_admission_or_after_upgrade_fails_closed() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, REST_POLICY).unwrap());
        let plain = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let (engine_with_admission, upgraded) = admitted_tunnel();
        upgraded.generation_guard().end_readmission();

        engine.reload(POLICY_REGO, REST_POLICY).unwrap();
        engine_with_admission
            .reload(POLICY_REGO, REST_POLICY)
            .unwrap();

        assert!(!plain.readmit_if_stale());
        assert!(!upgraded.readmit_if_stale());
    }

    #[test]
    fn standalone_guard_is_readmitted_but_tunnel_guard_moves_only_with_its_engine() {
        let (engine, tunnel) = admitted_tunnel();
        let readmission = tunnel.generation_guard().readmission.clone().unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap()
            .with_readmission(Arc::clone(&readmission));
        engine.reload(POLICY_REGO, UNRELATED_RULE_ADDED).unwrap();

        assert!(!tunnel.generation_guard().readmit_if_stale());
        assert!(guard.readmit_if_stale());
        assert_eq!(guard.captured_generation(), engine.current_generation());
    }

    #[tokio::test]
    async fn revocation_wait_ignores_reloads_that_still_admit_the_tunnel() {
        let (engine, tunnel) = admitted_tunnel();
        let guard = tunnel.generation_guard().clone();
        let wait = tokio::spawn(async move { guard.wait_until_revoked().await });

        engine.reload(POLICY_REGO, UNRELATED_RULE_ADDED).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!wait.is_finished(), "an admitting reload must not revoke");

        engine.reload(POLICY_REGO, HOST_REMOVED).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), wait)
            .await
            .expect("a denying reload must revoke")
            .unwrap();
    }
}
