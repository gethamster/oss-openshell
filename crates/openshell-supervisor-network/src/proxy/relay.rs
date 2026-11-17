// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared relay primitives for authorized explicit-proxy egress.

use super::{EgressDecision, L7RouteSnapshot, emit_l7_tunnel_close_after_policy_change};
use crate::l7::relay::L7EvalContext;
use crate::opa::{
    NetworkAction, OpaEngine, PolicyGenerationGuard, TunnelPolicyEngine, TunnelReadmission,
};
use miette::{IntoDiagnostic, Result};
use openshell_core::activity::ActivitySender;
use openshell_core::endpoint_status::EndpointObservationSender;
use openshell_core::secrets::SecretResolver;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

enum PreparedHttpPolicy {
    Inspect {
        configs: Vec<crate::l7::L7EndpointConfig>,
        evaluator: Box<TunnelPolicyEngine>,
    },
    Passthrough {
        generation_guard: PolicyGenerationGuard,
    },
}

/// Everything an HTTP relay needs after authorization is complete.
///
/// The relay owns a generation-pinned policy primitive. Its only route to the
/// mutable OPA engine is re-admission: after a reload, the original CONNECT
/// authorization runs again, and the tunnel moves to the current generation
/// only when the result is identical. Otherwise policy reloads fail closed
/// through the guard or tunnel evaluator already attached here.
pub(super) struct RelayContext<'a> {
    request: &'a L7EvalContext,
    policy: PreparedHttpPolicy,
    middleware_engine: &'a OpaEngine,
}

/// Non-blocking observation channels attached to an authorized HTTP relay.
pub(super) struct RelaySignals {
    /// Receives general sandbox network activity.
    pub(super) activity: Option<ActivitySender>,
    /// Receives terminal tool server results for endpoint status reporting.
    pub(super) endpoint_observation: Option<EndpointObservationSender>,
}

/// Build the request-processing context shared by CONNECT and forward HTTP.
pub(super) fn http_context(
    decision: &EgressDecision,
    provider_credentials: Option<openshell_core::provider_credentials::ProviderCredentialState>,
    secret_resolver: Option<Arc<SecretResolver>>,
    policy_local: Option<&crate::policy_local::PolicyLocalContext>,
    agent_proposals: openshell_core::proposals::AgentProposals,
    signals: RelaySignals,
) -> L7EvalContext {
    // Provider-backed credentials must be acquired from the live state for
    // each request after middleware/token-grant awaits. Keep only the legacy
    // resolver fallback when no live provider state exists.
    let secret_resolver = provider_credentials
        .is_none()
        .then_some(secret_resolver)
        .flatten();
    // Grants use the owning sandbox instance's resolver; without one they fail closed.
    let token_grant_resolver = provider_credentials
        .as_ref()
        .and(policy_local)
        .and_then(crate::policy_local::PolicyLocalContext::token_grant_resolver);
    let workspace = policy_local
        .map(crate::policy_local::PolicyLocalContext::workspace)
        .unwrap_or_default();
    let policy_name = match &decision.action {
        NetworkAction::Allow { matched_policy } => matched_policy.clone().unwrap_or_default(),
        NetworkAction::Deny { .. } => String::new(),
    };

    L7EvalContext {
        host: decision.intent.destination.host.clone(),
        port: decision.intent.destination.port,
        request_default_port: None,
        policy_name,
        binary_path: decision
            .binary
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
        ancestors: decision
            .ancestors
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        cmdline_paths: decision
            .cmdline_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        secret_resolver,
        provider_credentials,
        provider_credential_revision: None,
        provider_credential_installation_id: None,
        body_classifier: None,
        activity_tx: signals.activity,
        token_grant_resolver,
        agent_proposals,
        workspace,
        endpoint_observation_tx: signals.endpoint_observation,
    }
}

/// Pin a generation for a relay or the forward HTTP single-request path.
pub(super) fn pin_policy_generation(
    opa_engine: &OpaEngine,
    expected_generation: u64,
) -> Result<PolicyGenerationGuard> {
    opa_engine.generation_guard(expected_generation)
}

/// Clone an L7 evaluator for a relay or the forward HTTP single-request path.
pub(super) fn pin_l7_evaluator(
    opa_engine: &OpaEngine,
    expected_generation: u64,
) -> Result<TunnelPolicyEngine> {
    opa_engine.clone_engine_for_tunnel(expected_generation)
}

pub(super) fn validate_route_generation(
    route: Option<&L7RouteSnapshot>,
    expected_generation: u64,
) -> Result<()> {
    if let Some(route) = route
        && route.l7_policy_generation != expected_generation
    {
        return Err(miette::miette!(
            "policy changed before CONNECT route hydration \
             [l4_generation:{} l7_generation:{}]",
            expected_generation,
            route.l7_policy_generation,
        ));
    }
    Ok(())
}

/// Build the state that lets a relay check its tunnel again after a policy
/// reload. `None` keeps the relay strictly pinned to its first generation.
fn tunnel_readmission(
    opa_engine: &Arc<OpaEngine>,
    decision: &EgressDecision,
) -> Option<Arc<TunnelReadmission>> {
    let admission = decision.endpoint.tunnel_admission(&decision.action)?;
    Some(TunnelReadmission::new(Arc::clone(opa_engine), admission))
}

/// Pin the decision's generation, or, when a reload already happened, the
/// current generation if the current policy re-admits the tunnel.
fn pin_or_readmit<T>(
    readmission: Option<&Arc<TunnelReadmission>>,
    pinned: Result<T>,
    readmit: impl FnOnce(&Arc<TunnelReadmission>) -> Result<Option<T>>,
    attach: impl FnOnce(T, Arc<TunnelReadmission>) -> T,
) -> Result<T> {
    let Some(readmission) = readmission else {
        return pinned;
    };
    let pinned = match pinned {
        Ok(pinned) => pinned,
        Err(error) => match readmit(readmission) {
            Ok(Some(readmitted)) => return Ok(readmitted),
            Ok(None) => return Err(error),
            Err(readmit_error) => {
                return Err(miette::miette!(
                    "{error}; tunnel re-admission failed: {readmit_error}"
                ));
            }
        },
    };
    Ok(attach(pinned, Arc::clone(readmission)))
}

/// Prepare a generation-pinned HTTP relay at the adapter boundary.
///
/// A stale generation is checked again against the current policy. When the
/// current policy no longer admits the tunnel with the same state, the
/// established CONNECT behavior applies: emit the policy-change close event
/// and let the adapter close the live tunnel without attempting to write an
/// HTTP response into it.
pub(super) fn prepare_http_relay<'a>(
    route: Option<&L7RouteSnapshot>,
    opa_engine: &'a Arc<OpaEngine>,
    decision: &EgressDecision,
    request: &'a L7EvalContext,
) -> Option<RelayContext<'a>> {
    if let Err(error) = validate_route_generation(route, decision.policy_generation) {
        emit_l7_tunnel_close_after_policy_change(
            &decision.intent.destination.host,
            decision.intent.destination.port,
            error,
        );
        return None;
    }

    let readmission = tunnel_readmission(opa_engine, decision);
    let policy = if let Some(route) = route.filter(|route| !route.configs.is_empty()) {
        let evaluator = match pin_or_readmit(
            readmission.as_ref(),
            pin_l7_evaluator(opa_engine, decision.policy_generation),
            TunnelReadmission::pin_tunnel,
            TunnelPolicyEngine::with_readmission,
        ) {
            Ok(evaluator) => evaluator,
            Err(error) => {
                emit_l7_tunnel_close_after_policy_change(
                    &decision.intent.destination.host,
                    decision.intent.destination.port,
                    error,
                );
                return None;
            }
        };
        let configs = route
            .configs
            .iter()
            .map(|snapshot| snapshot.config.clone())
            .collect();
        PreparedHttpPolicy::Inspect {
            configs,
            evaluator: Box::new(evaluator),
        }
    } else {
        let generation_guard = match pin_or_readmit(
            readmission.as_ref(),
            pin_policy_generation(opa_engine, decision.policy_generation),
            TunnelReadmission::pin_guard,
            PolicyGenerationGuard::with_readmission,
        ) {
            Ok(guard) => guard,
            Err(error) => {
                emit_l7_tunnel_close_after_policy_change(
                    &decision.intent.destination.host,
                    decision.intent.destination.port,
                    error,
                );
                return None;
            }
        };
        PreparedHttpPolicy::Passthrough { generation_guard }
    };

    Some(RelayContext {
        request,
        policy,
        middleware_engine: opa_engine,
    })
}

/// Pin the generation used by a raw relay so policy activation or quarantine
/// closes streams that otherwise have no request boundary at which to notice
/// a stale decision.
pub(super) fn prepare_raw_relay(
    route: Option<&L7RouteSnapshot>,
    opa_engine: &OpaEngine,
    decision: &EgressDecision,
) -> Option<PolicyGenerationGuard> {
    if let Err(error) = validate_route_generation(route, decision.policy_generation) {
        emit_l7_tunnel_close_after_policy_change(
            &decision.intent.destination.host,
            decision.intent.destination.port,
            error,
        );
        return None;
    }

    match pin_policy_generation(opa_engine, decision.policy_generation) {
        Ok(guard) => Some(guard),
        Err(error) => {
            emit_l7_tunnel_close_after_policy_change(
                &decision.intent.destination.host,
                decision.intent.destination.port,
                error,
            );
            None
        }
    }
}

/// Relay an HTTP/1 stream using an already-authorized, generation-pinned context.
///
/// A policy reload closes the stream at once unless the current policy still
/// admits the tunnel with the same connect-time state. A re-admitted stream
/// moves to the current generation at its next request boundary; checks
/// inside an in-flight exchange stay fail-closed.
///
/// CONNECT plaintext and TLS-terminated streams both enter through this
/// function. Forward HTTP will provide a buffered first request to the same
/// boundary in the next migration step.
pub(super) async fn relay_http_stream<C, U>(
    client: &mut C,
    upstream: &mut U,
    context: RelayContext<'_>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    match context.policy {
        PreparedHttpPolicy::Inspect { configs, evaluator } if configs.len() == 1 => {
            let generation_guard = evaluator.generation_guard().clone();
            tokio::select! {
                result = crate::l7::relay::relay_with_inspection(
                    &configs[0],
                    *evaluator,
                    client,
                    upstream,
                    context.request,
                ) => result,
                () = generation_guard.wait_until_revoked() => {
                    emit_stale_relay_close(context.request, &generation_guard);
                    Ok(())
                }
            }
        }
        PreparedHttpPolicy::Inspect { configs, evaluator } => {
            let generation_guard = evaluator.generation_guard().clone();
            tokio::select! {
                result = crate::l7::relay::relay_with_route_selection(
                    &configs,
                    *evaluator,
                    client,
                    upstream,
                    context.request,
                ) => result,
                () = generation_guard.wait_until_revoked() => {
                    emit_stale_relay_close(context.request, &generation_guard);
                    Ok(())
                }
            }
        }
        PreparedHttpPolicy::Passthrough { generation_guard } => {
            tokio::select! {
                result = crate::l7::relay::relay_passthrough_with_credentials(
                    client,
                    upstream,
                    context.request,
                    &generation_guard,
                    Some(context.middleware_engine),
                ) => result,
                () = generation_guard.wait_until_revoked() => {
                    emit_stale_relay_close(context.request, &generation_guard);
                    Ok(())
                }
            }
        }
    }
}

// Exercise the production single/multiple-route dispatch from L7 fixtures.
#[cfg(test)]
pub async fn relay_inspected_http_stream_for_test<C, U>(
    client: &mut C,
    upstream: &mut U,
    configs: Vec<crate::l7::L7EndpointConfig>,
    evaluator: TunnelPolicyEngine,
    middleware_engine: &OpaEngine,
    request: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    relay_http_stream(
        client,
        upstream,
        RelayContext {
            request,
            policy: PreparedHttpPolicy::Inspect {
                configs,
                evaluator: Box::new(evaluator),
            },
            middleware_engine,
        },
    )
    .await
}

/// Relay a policy-authorized raw TCP stream.
pub(super) async fn relay_tcp<C, U>(
    client: &mut C,
    upstream: &mut U,
    generation_guard: &PolicyGenerationGuard,
    request: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        result = tokio::io::copy_bidirectional(client, upstream) => {
            result.into_diagnostic()?;
        }
        () = generation_guard.wait_until_stale() => {
            emit_stale_relay_close(request, generation_guard);
        }
    }
    Ok(())
}

fn emit_stale_relay_close(request: &L7EvalContext, guard: &PolicyGenerationGuard) {
    emit_l7_tunnel_close_after_policy_change(
        &request.host,
        request.port,
        miette::miette!(
            "policy generation is stale [captured_generation:{} current_generation:{}]",
            guard.captured_generation(),
            guard.current_generation(),
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::super::{EgressIntent, EndpointDecision, ProcessIdentityEvidence};
    use super::*;

    const POLICY_REGO: &str = include_str!("../../data/sandbox-policy.rego");
    const EMPTY_POLICY_DATA: &str = "network_policies: {}\n";

    fn decision(policy_generation: u64) -> EgressDecision {
        EgressDecision {
            intent: EgressIntent::connect("example.com".to_string(), 80),
            action: NetworkAction::Allow {
                matched_policy: Some("test".to_string()),
            },
            policy_generation,
            identity: ProcessIdentityEvidence::Available,
            endpoint: EndpointDecision::default(),
            binary: None,
            binary_pid: None,
            ancestors: vec![],
            cmdline_paths: vec![],
        }
    }

    fn request_context() -> L7EvalContext {
        L7EvalContext {
            host: "example.com".to_string(),
            port: 80,
            request_default_port: Some(80),
            policy_name: "test".to_string(),
            binary_path: String::new(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            provider_credentials: None,
            provider_credential_revision: None,
            provider_credential_installation_id: None,
            body_classifier: None,
            activity_tx: None,
            token_grant_resolver: None,
            agent_proposals: openshell_core::proposals::AgentProposals::default(),
            workspace: String::new(),
            endpoint_observation_tx: None,
        }
    }

    async fn assert_response_lifecycle<C, P>(mut caller: C, mut client: P)
    where
        C: AsyncRead + AsyncWrite + Unpin,
        P: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut upstream, mut server) = tokio::io::duplex(1024);
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(engine.current_generation());
        let request = request_context();
        let context = prepare_http_relay(None, &engine, &decision, &request).unwrap();
        let persistent = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        // Larger than either transport buffer: closing must drain the body.
        let body = vec![b'x'; 64 * 1024];
        let mut closing = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        closing.extend_from_slice(&body);
        let relay = Box::pin(relay_http_stream(&mut client, &mut upstream, context));
        let serve = async {
            for response in [persistent.as_slice(), closing.as_slice()] {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(server.read_u8().await.unwrap());
                    assert!(request.len() < 4096);
                }
                assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
                server.write_all(response).await.unwrap();
                server.flush().await.unwrap();
            }
            // Retain the upstream socket: response headers decide persistence.
        };
        let receive = async {
            let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            caller.write_all(request).await.unwrap();
            caller.flush().await.unwrap();
            let mut first = vec![0; persistent.len()];
            caller.read_exact(&mut first).await.unwrap();
            assert_eq!(first, persistent);
            // A real second exchange verifies reuse, without a timing assertion.
            caller.write_all(request).await.unwrap();
            caller.flush().await.unwrap();
            let mut second = Vec::new();
            // TLS must return clean EOF, not UnexpectedEof from a dropped socket.
            caller.read_to_end(&mut second).await.unwrap();
            assert_eq!(second, closing);
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (result, (), ()) = tokio::join!(relay, serve, receive);
            result.unwrap();
        })
        .await
        .expect("response delivery and EOF must not await another request");
    }

    #[tokio::test]
    async fn http_relay_reuses_then_closes_after_complete_response() {
        let (caller, client) = tokio::io::duplex(1024);
        assert_response_lifecycle(caller, client).await;
    }

    #[tokio::test]
    async fn tls_http_relay_reuses_then_sends_close_notify_after_complete_response() {
        use crate::l7::tls::{CertCache, ProxyTlsState, SandboxCa, tls_terminate_client};
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let ca = SandboxCa::generate().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_reader_iter(&mut ca.cert_pem().as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = Arc::new(
            openshell_crypto::tls::client_builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let state = ProxyTlsState::new(CertCache::new(ca), config.clone());
        let connector = tokio_rustls::TlsConnector::from(config);
        let (caller, client) = tokio::io::duplex(1024);
        let (caller, client) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                connector.connect(
                    rustls::pki_types::ServerName::try_from("example.com").unwrap(),
                    caller
                ),
                tls_terminate_client(client, &state, "example.com"),
            )
        })
        .await
        .expect("TLS handshake must complete");
        assert_response_lifecycle(caller.unwrap(), client.unwrap()).await;
    }

    #[test]
    fn relay_without_route_pins_l4_decision_generation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(engine.current_generation());
        let request = request_context();

        let context = prepare_http_relay(None, &engine, &decision, &request)
            .expect("current L4 generation should prepare a relay");
        let PreparedHttpPolicy::Passthrough { generation_guard } = context.policy else {
            panic!("route-less relay should use a generation guard");
        };

        assert_eq!(
            generation_guard.captured_generation(),
            decision.policy_generation
        );
    }

    #[test]
    fn empty_hydrated_route_cannot_replace_stale_l4_generation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![],
            l7_policy_generation: engine.current_generation(),
        };
        let request = request_context();

        assert!(
            prepare_http_relay(Some(&route), &engine, &decision, &request).is_none(),
            "a current L7 lookup must not freshen a stale L4 allow"
        );
    }

    #[test]
    fn inspected_route_cannot_replace_stale_l4_generation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![super::super::L7ConfigSnapshot {
                config: crate::l7::L7EndpointConfig {
                    protocol: crate::l7::L7Protocol::Rest,
                    endpoint_id: String::new(),
                    policy_hash: String::new(),
                    path: "/**".to_string(),
                    tls: crate::l7::TlsMode::Auto,
                    enforcement: crate::l7::EnforcementMode::Enforce,
                    graphql_max_body_bytes: crate::l7::graphql::DEFAULT_MAX_BODY_BYTES,
                    json_rpc_max_body_bytes: crate::l7::jsonrpc::DEFAULT_MAX_BODY_BYTES,
                    mcp_strict_tool_names: true,
                    mcp_versions: Vec::new(),
                    allow_encoded_slash: false,
                    websocket_credential_rewrite: false,
                    request_body_credential_rewrite: false,
                    allow_uninspected_credentials: false,
                    provider_credentialed: false,
                    websocket_graphql_policy: false,
                    credential_signing: crate::l7::CredentialSigning::None,
                    signing_service: String::new(),
                    signing_region: String::new(),
                },
            }],
            l7_policy_generation: engine.current_generation(),
        };
        let request = request_context();

        assert!(
            prepare_http_relay(Some(&route), &engine, &decision, &request).is_none(),
            "an inspected route must use the generation that authorized CONNECT"
        );
    }

    #[test]
    fn raw_route_cannot_replace_stale_l4_generation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![],
            l7_policy_generation: engine.current_generation(),
        };

        assert!(
            prepare_raw_relay(Some(&route), &engine, &decision).is_none(),
            "a raw relay must not freshen a stale L4 allow"
        );
    }

    #[test]
    fn stale_generation_fails_before_relay_context_is_created() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(engine.current_generation());
        let request = request_context();
        engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();

        assert!(
            prepare_http_relay(None, &engine, &decision, &request).is_none(),
            "policy reload must prevent a stale relay from starting"
        );
    }

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

    fn rest_policy_with(extra: &str) -> String {
        format!("{REST_POLICY}{extra}")
    }

    const REPOSITORY_RULE: &str = r"  repository:
    name: repository
    endpoints:
      - host: github.example.test
        port: 443
    binaries:
      - { path: /usr/bin/git }
";

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

    const RULE_DENIES: &str = r#"
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

    /// Authorize a CONNECT the way the proxy does, keeping the exact input.
    fn admitted_rest_decision(engine: &OpaEngine) -> (EgressDecision, L7RouteSnapshot) {
        let input = crate::opa::NetworkInput {
            host: "api.example.test".into(),
            port: 8080,
            binary_path: std::path::PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let authorization = engine.authorize_egress(&input).unwrap();
        let decision = EgressDecision {
            intent: EgressIntent::connect("api.example.test".into(), 8080),
            action: authorization.action.clone(),
            policy_generation: authorization.generation,
            identity: ProcessIdentityEvidence::Available,
            endpoint: EndpointDecision::from_authorization(&authorization, &input),
            binary: Some(input.binary_path.clone()),
            binary_pid: None,
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let route = super::super::query_l7_route_snapshot(&decision, "api.example.test", 8080)
            .expect("REST route");
        (decision, route)
    }

    fn rest_request_context() -> L7EvalContext {
        L7EvalContext {
            host: "api.example.test".to_string(),
            port: 8080,
            request_default_port: Some(8080),
            policy_name: "rest_api".to_string(),
            binary_path: "/usr/bin/curl".to_string(),
            ..request_context()
        }
    }

    /// Send one keep-alive request. Returns `true` when it reached upstream
    /// and its response reached the client.
    async fn exchange(
        app: &mut tokio::io::DuplexStream,
        upstream: &mut tokio::io::DuplexStream,
    ) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        if app
            .write_all(b"GET /models HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
            .await
            .is_err()
        {
            // The relay already closed the tunnel.
            return false;
        }
        let mut request = [0u8; 512];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut request),
        )
        .await
        .expect("upstream must see a request or EOF")
        .unwrap();
        if read == 0 {
            return false;
        }
        assert!(request[..read].starts_with(b"GET /models HTTP/1.1\r\n"));
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();
        let mut response = [0u8; 512];
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("client must see the response")
            .unwrap();
        String::from_utf8_lossy(&response[..read]).contains("200 OK")
    }

    /// Run an inspected CONNECT relay across policy reloads. Each item of
    /// `reloads` is applied after one successful exchange; the result says
    /// which exchanges after a reload still reached upstream.
    async fn relay_across_reloads(reloads: &[&str]) -> Vec<bool> {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, REST_POLICY).unwrap());
        let (decision, route) = admitted_rest_decision(&engine);
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay_engine = Arc::clone(&engine);
        let relay = tokio::spawn(async move {
            let request = rest_request_context();
            let context = prepare_http_relay(Some(&route), &relay_engine, &decision, &request)
                .expect("current generation prepares the relay");
            assert!(matches!(context.policy, PreparedHttpPolicy::Inspect { .. }));
            relay_http_stream(&mut relay_client, &mut relay_upstream, context).await
        });

        assert!(exchange(&mut app, &mut upstream).await);
        let mut results = Vec::new();
        for reloaded in reloads {
            engine.reload(POLICY_REGO, reloaded).unwrap();
            // Let the relay's reload watcher run before the next request.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let forwarded = exchange(&mut app, &mut upstream).await;
            results.push(forwarded);
            if !forwarded {
                break;
            }
        }
        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay must finish")
            .unwrap()
            .unwrap();
        results
    }

    #[tokio::test]
    async fn stale_tunnel_continues_while_current_policy_still_admits_it() {
        let unrelated = rest_policy_with(REPOSITORY_RULE);
        // A reload that only adds rules for another host keeps the tunnel,
        // and a later reload that removes its host still closes it.
        assert_eq!(
            relay_across_reloads(&[&unrelated, REST_POLICY, HOST_REMOVED]).await,
            vec![true, true, false]
        );
    }

    #[tokio::test]
    async fn stale_tunnel_closes_when_host_is_removed() {
        assert_eq!(relay_across_reloads(&[HOST_REMOVED]).await, vec![false]);
    }

    #[tokio::test]
    async fn stale_tunnel_closes_when_binary_is_removed() {
        assert_eq!(relay_across_reloads(&[BINARY_REMOVED]).await, vec![false]);
    }

    #[tokio::test]
    async fn stale_tunnel_closes_when_l7_rule_now_denies_the_request() {
        assert_eq!(relay_across_reloads(&[RULE_DENIES]).await, vec![false]);
    }

    #[tokio::test]
    async fn stale_tunnel_closes_under_fail_closed_quarantine() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, REST_POLICY).unwrap());
        let (decision, route) = admitted_rest_decision(&engine);
        let (_app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, _upstream) = tokio::io::duplex(8192);
        let relay_engine = Arc::clone(&engine);
        let relay = tokio::spawn(async move {
            let request = rest_request_context();
            let context =
                prepare_http_relay(Some(&route), &relay_engine, &decision, &request).unwrap();
            relay_http_stream(&mut relay_client, &mut relay_upstream, context).await
        });
        tokio::task::yield_now().await;

        engine.enter_fail_closed("candidate policy failed").unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("quarantine must close the idle tunnel")
            .unwrap()
            .unwrap();
    }

    #[test]
    fn relay_started_after_admitting_reload_uses_current_generation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, REST_POLICY).unwrap());
        let (decision, route) = admitted_rest_decision(&engine);
        engine
            .reload(POLICY_REGO, &rest_policy_with(REPOSITORY_RULE))
            .unwrap();
        let request = rest_request_context();

        let context = prepare_http_relay(Some(&route), &engine, &decision, &request)
            .expect("an admitting reload must not stop the relay");
        let PreparedHttpPolicy::Inspect { evaluator, .. } = context.policy else {
            panic!("REST route should be inspected");
        };
        assert_eq!(evaluator.captured_generation(), engine.current_generation());

        engine.reload(POLICY_REGO, HOST_REMOVED).unwrap();
        assert!(
            prepare_http_relay(Some(&route), &engine, &decision, &request).is_none(),
            "a denying reload must stop the relay"
        );
    }

    #[tokio::test]
    async fn raw_relay_closes_immediately_when_fail_closed_generation_is_published() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let request = request_context();
        let (_client_peer, mut proxy_client) = tokio::io::duplex(64);
        let (_upstream_peer, mut proxy_upstream) = tokio::io::duplex(64);

        let relay = tokio::spawn(async move {
            relay_tcp(&mut proxy_client, &mut proxy_upstream, &guard, &request).await
        });
        tokio::task::yield_now().await;

        engine
            .enter_fail_closed("candidate policy validation failed")
            .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("raw relay should close when its generation becomes stale")
            .expect("relay task should not panic")
            .expect("stale relay closure should be clean");
    }
}
