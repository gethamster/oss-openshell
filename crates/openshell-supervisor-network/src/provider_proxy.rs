// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0
//! Provider-aware mediation for one externally fenced VM.
//!
//! The caller owns the VM/Pod identity, source isolation and infrastructure
//! lease. This runtime owns the same TLS, policy and credential machinery as
//! the native supervisor. It never claims guest executable identity.

use crate::{
    opa::OpaEngine,
    run::{Networking, ProxyTlsFiles, SandboxInstanceNetwork, run_networking},
};
use miette::{IntoDiagnostic, Result};
pub use openshell_core::grpc_client::{GatewayCredentials, GatewayEndpoint};
use openshell_core::{
    grpc_client::ProviderEnvironmentResult,
    policy::{NetworkMode, NetworkPolicy, ProxyPolicy},
    proposals::AgentProposals,
    proto::{
        GetSandboxConfigResponse, GetSandboxProviderEnvironmentResponse, ProviderReadinessReason,
        SandboxPolicy,
    },
    provider_credentials::ProviderCredentialState,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, atomic::AtomicU32},
};

/// Host-owned lease and public-address checks. An empty address set checks
/// authority only. Every resolved address is checked before any upstream dial.
pub trait DestinationGuard: Send + Sync {
    /// Reject protected infrastructure names before their DNS lookup.
    fn check_host(&self, _host: &str) -> std::result::Result<(), String> {
        Ok(())
    }
    fn check(&self, addresses: &[SocketAddr]) -> std::result::Result<(), String>;
}

/// One listener must be reachable only by its assigned VM, as enforced by the
/// caller's host fence. Never share it across tenants or VM generations.
pub struct ProxyOptions {
    pub sandbox_id: String,
    pub bind: SocketAddr,
    pub tls_directory: PathBuf,
    pub gateway: Option<GatewayEndpoint>,
    pub destination_guard: Arc<dyn DestinationGuard>,
}

/// The complete safe material to install in the assigned guest.
/// Credential values have already been replaced by endpoint-bound handles.
#[derive(Clone, Serialize, Deserialize)]
pub struct GuestMaterial {
    pub mediation_generation: u64,
    pub environment: HashMap<String, String>,
    pub files: HashMap<String, String>,
    pub ca_certificate: String,
    pub config_revision: u64,
    pub provider_revision: u64,
    pub policy_hash: String,
    pub provider_attachment_epoch: String,
}

/// A fail-closed proxy whose credential state cannot escape through its API.
pub struct ProviderProxy {
    networking: Networking,
    engine: Arc<OpaEngine>,
    credentials: ProviderCredentialState,
    gateway_credentials: Option<GatewayCredentials>,
    guard: Arc<dyn DestinationGuard>,
    state: Mutex<ProxyState>,
    ca_certificate: String,
}

#[derive(Default)]
struct ProxyState {
    high_water: u64,
    installed: Option<GuestMaterial>,
}

impl ProviderProxy {
    /// Bind in deny-all state. `apply` must install an admitted snapshot before
    /// guest traffic is permitted. The caller retains and revokes its own lease.
    pub async fn start(options: ProxyOptions) -> Result<Self> {
        if options.sandbox_id.is_empty() || options.bind.port() == 0 {
            miette::bail!("explicit VM identity and proxy port required");
        }
        std::fs::create_dir_all(&options.tls_directory).into_diagnostic()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &options.tls_directory,
                std::fs::Permissions::from_mode(0o700),
            )
            .into_diagnostic()?;
        }
        let empty = SandboxPolicy {
            version: 1,
            ..Default::default()
        };
        let engine = Arc::new(OpaEngine::from_vm_policy(&empty)?);
        engine.set_destination_guard(options.destination_guard.clone())?;
        engine.enter_fail_closed("VM provider configuration not installed")?;
        let credentials = ProviderCredentialState::from_child_env_snapshot(0, HashMap::new());
        let policy = openshell_core::policy::SandboxPolicy {
            version: 1,
            filesystem: openshell_core::policy::FilesystemPolicy::default(),
            network: NetworkPolicy {
                mode: NetworkMode::Proxy,
                proxy: Some(ProxyPolicy {
                    http_addr: Some(options.bind),
                }),
            },
            landlock: openshell_core::policy::LandlockPolicy::default(),
            process: openshell_core::policy::ProcessPolicy::default(),
        };
        let gateway_credentials = options
            .gateway
            .as_ref()
            .map(|gateway| gateway.credentials().clone());
        let (_, workspace) = tokio::sync::watch::channel(String::new());
        let networking = run_networking(
            &policy,
            Some(options.bind.ip()),
            Some(&engine),
            None,
            Arc::new(AtomicU32::new(0)),
            false,
            &credentials,
            SandboxInstanceNetwork {
                sandbox_id: Some(options.sandbox_id),
                gateway: options.gateway,
                proxy_tls: ProxyTlsFiles {
                    directory: Some(options.tls_directory),
                    ..Default::default()
                },
                ..Default::default()
            },
            None,
            None,
            None,
            AgentProposals::new(false),
            workspace,
            &crate::upstream_proxy::UpstreamProxyArgs::default(),
            None,
            None,
            #[cfg(target_os = "linux")]
            None,
            None,
            None,
            None,
        )
        .await?;
        let ca_path = networking
            .ca_file_paths
            .as_ref()
            .ok_or_else(|| miette::miette!("proxy CA unavailable"))?
            .0
            .clone();
        let ca_certificate = std::fs::read_to_string(ca_path).into_diagnostic()?;
        Ok(Self {
            networking,
            engine,
            credentials,
            gateway_credentials,
            guard: options.destination_guard,
            state: Mutex::new(ProxyState::default()),
            ca_certificate,
        })
    }

    /// Apply matching native protobuf snapshots from the authenticated gateway.
    /// The API deliberately takes wire bytes so external drivers need not
    /// duplicate or cast generated protobuf types across crate versions.
    pub fn apply(
        &self,
        generation: u64,
        config: &[u8],
        environment: &[u8],
    ) -> Result<GuestMaterial> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| miette::miette!("proxy state unavailable"))?;
        if generation == 0
            || generation < state.high_water
            || (generation == state.high_water && state.installed.is_none())
        {
            miette::bail!("stale mediation generation");
        }
        state.high_water = generation;
        let result =
            self.prepare_and_install(generation, config, environment, state.installed.as_ref());
        match result {
            Ok(material) => {
                state.installed = Some(material.clone());
                Ok(material)
            }
            Err(error) => {
                self.engine
                    .enter_fail_closed("VM provider snapshot rejected")?;
                self.credentials
                    .revoke_static_provider_environment(self.credentials.revision());
                state.installed = None;
                Err(error)
            }
        }
    }

    fn prepare_and_install(
        &self,
        generation: u64,
        config: &[u8],
        environment: &[u8],
        installed: Option<&GuestMaterial>,
    ) -> Result<GuestMaterial> {
        if config.len() > 4 * 1024 * 1024 || environment.len() > 4 * 1024 * 1024 {
            miette::bail!("provider snapshot exceeds limit");
        }
        self.guard
            .check(&[])
            .map_err(|_| miette::miette!("external VM lease is inactive"))?;
        let config = GetSandboxConfigResponse::decode(config).into_diagnostic()?;
        let environment =
            GetSandboxProviderEnvironmentResponse::decode(environment).into_diagnostic()?;
        if !config.configuration_admitted
            || !config.supervisor_middleware_services.is_empty()
            || environment.readiness_reason != 0
            || environment.provider_env_revision != config.provider_env_revision
            || environment.provider_attachment_epoch != config.provider_attachment_epoch
            || environment.policy_hash != config.policy_hash
            || (self.credentials.requires_stable_placeholders()
                && !environment.supports_stable_placeholder_environment_keys)
        {
            miette::bail!("provider snapshots are unadmitted or do not match");
        }
        let policy = config
            .policy
            .as_ref()
            .ok_or_else(|| miette::miette!("effective provider policy missing"))?;
        validate_vm_policy(policy)?;
        if openshell_core::policy_identity::deterministic_policy_hash(policy) != config.policy_hash
        {
            miette::bail!("effective policy hash mismatch");
        }
        if let Some(installed) = installed {
            let unchanged = (
                installed.config_revision,
                installed.provider_revision,
                &installed.policy_hash,
                &installed.provider_attachment_epoch,
            ) == (
                config.config_revision,
                config.provider_env_revision,
                &config.policy_hash,
                &config.provider_attachment_epoch,
            );
            if installed.mediation_generation == generation && !unchanged {
                miette::bail!("mediation generation reused for another snapshot");
            }
            if unchanged && self.engine.fail_closed_reason().is_none() {
                return Ok(GuestMaterial {
                    mediation_generation: generation,
                    ..installed.clone()
                });
            }
        }
        let environment = ProviderEnvironmentResult::try_from(environment)?;
        if environment.readiness_reason != ProviderReadinessReason::Unspecified {
            miette::bail!("provider credentials are not ready");
        }
        let prepared = ProviderCredentialState::from_bound_environment_with_stable_placeholders(
            environment.provider_env_revision,
            environment.environment,
            environment.credential_expires_at_ms,
            environment.dynamic_credentials,
            environment.static_credential_bindings,
            environment.non_secret_environment_keys,
            environment.stable_placeholder_environment_keys,
        )
        .map_err(|_| miette::miette!("invalid provider credential bindings"))?;
        prepared.set_managed_files(environment.files);
        let safe = prepared.child_environment_snapshot().into_diagnostic()?;
        self.engine
            .reload_configuration_from_proto_with_pid(policy, 0, None, || {
                self.credentials.install_prepared(&prepared);
            })?;
        Ok(GuestMaterial {
            mediation_generation: generation,
            environment: safe.environment,
            files: safe.files,
            ca_certificate: self.ca_certificate.clone(),
            config_revision: config.config_revision,
            provider_revision: config.provider_env_revision,
            policy_hash: config.policy_hash,
            provider_attachment_epoch: config.provider_attachment_epoch,
        })
    }

    /// Install the lifecycle owner's renewed scoped gateway JWT. This slot
    /// does not run an independent renewal loop or expose its token to guests.
    pub fn update_gateway_credentials(&self, token: &str) -> Result<()> {
        self.gateway_credentials
            .as_ref()
            .ok_or_else(|| miette::miette!("gateway credentials not configured"))?
            .update_external_token(token)
    }

    /// Revoke before fencing or replacing a generation. Advancing OPA's
    /// generation cancels in-flight relays as well as denying new connections.
    pub fn revoke(&self, _reason: &str) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| miette::miette!("proxy state unavailable"))?;
        if state.installed.is_none() && self.engine.fail_closed_reason().is_some() {
            return Ok(());
        }
        self.engine.enter_fail_closed("external VM lease revoked")?;
        self.credentials
            .revoke_static_provider_environment(self.credentials.revision());
        state.installed = None;
        Ok(())
    }

    pub fn active_connections(&self) -> usize {
        self.networking
            .proxy
            .as_ref()
            .map_or(0, crate::proxy::ProxyHandle::active_connections)
    }
}

fn validate_vm_policy(policy: &SandboxPolicy) -> Result<()> {
    if policy.version != 1
        || policy.filesystem.is_some()
        || policy.process.is_some()
        || policy.landlock.is_some()
        || !policy.network_middlewares.is_empty()
    {
        miette::bail!("VM mediation cannot enforce guest filesystem or process claims");
    }
    for rule in policy.network_policies.values() {
        if rule.binaries.is_empty() || rule.binaries.iter().any(|binary| binary.path != "/**") {
            miette::bail!("VM provider policy requires explicit all-executable scope");
        }
    }
    Ok(())
}

impl Drop for ProviderProxy {
    fn drop(&mut self) {
        let _ = self.engine.enter_fail_closed("VM provider proxy stopped");
        self.credentials
            .revoke_static_provider_environment(self.credentials.revision());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        NetworkBinary, NetworkEndpoint, NetworkPolicyRule, StaticCredentialBinding,
        StaticCredentialEndpointBinding,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Guard {
        live: AtomicBool,
        checked: AtomicBool,
    }
    impl DestinationGuard for Guard {
        fn check(&self, addresses: &[SocketAddr]) -> std::result::Result<(), String> {
            if !self.live.load(Ordering::Acquire) {
                return Err("lease expired".into());
            }
            if !addresses.is_empty() {
                self.checked.store(true, Ordering::Release);
                return Err("test denies every dial".into());
            }
            Ok(())
        }
    }
    fn snapshots(path: &str) -> (Vec<u8>, Vec<u8>) {
        let policy = SandboxPolicy {
            version: 1,
            network_policies: HashMap::from([(
                "provider".into(),
                NetworkPolicyRule {
                    name: "provider".into(),
                    binaries: vec![NetworkBinary { path: path.into() }],
                    endpoints: vec![NetworkEndpoint {
                        host: "93.184.216.34".into(),
                        port: 443,
                        protocol: "rest".into(),
                        enforcement: 1,
                        access: 2,
                        ..Default::default()
                    }],
                },
            )]),
            ..Default::default()
        };
        let policy_hash = openshell_core::policy_identity::deterministic_policy_hash(&policy);
        let config = GetSandboxConfigResponse {
            configuration_admitted: true,
            policy: Some(policy),
            config_revision: 3,
            provider_env_revision: 7,
            provider_attachment_epoch: "epoch".into(),
            policy_hash: policy_hash.clone(),
            ..Default::default()
        };
        let provider = GetSandboxProviderEnvironmentResponse {
            environment: HashMap::from([(
                "TOKEN".into(),
                "synthetic-credential-not-for-guest".into(),
            )]),
            static_credential_bindings: HashMap::from([(
                "TOKEN".into(),
                StaticCredentialBinding {
                    endpoints: vec![StaticCredentialEndpointBinding {
                        host: "93.184.216.34".into(),
                        port: 443,
                        path: "/**".into(),
                    }],
                    credential_identity: "fixture:TOKEN".into(),
                    workload_credential_handle: "a".repeat(64),
                },
            )]),
            stable_placeholder_environment_keys: vec!["TOKEN".into()],
            supports_stable_placeholder_environment_keys: true,
            provider_env_revision: 7,
            provider_attachment_epoch: "epoch".into(),
            policy_hash,
            ..Default::default()
        };
        (config.encode_to_vec(), provider.encode_to_vec())
    }
    async fn start() -> (ProviderProxy, Arc<Guard>, tempfile::TempDir, SocketAddr) {
        let address = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("test port")
            .local_addr()
            .expect("test address");
        let directory = tempfile::tempdir().expect("private TLS directory");
        let guard = Arc::new(Guard {
            live: AtomicBool::new(true),
            checked: AtomicBool::new(false),
        });
        let proxy = ProviderProxy::start(ProxyOptions {
            sandbox_id: "vm-fixture".into(),
            bind: address,
            tls_directory: directory.path().into(),
            gateway: None,
            destination_guard: guard.clone(),
        })
        .await
        .expect("start VM proxy");
        (proxy, guard, directory, address)
    }

    #[tokio::test]
    async fn paired_snapshots_install_placeholders_and_revoke_on_mismatch() {
        let (proxy, guard, _directory, _) = start().await;
        let (config, provider) = snapshots("/**");
        let material = proxy
            .apply(1, &config, &provider)
            .expect("paired snapshots");
        assert!(!material.environment["TOKEN"].contains("synthetic-credential"));
        assert!(material.environment["TOKEN"].starts_with("openshell:resolve:env:"));
        assert_eq!(
            proxy
                .credentials
                .resolver_for_endpoint("93.184.216.34", 443, "/chat")
                .expect("bound resolver")
                .resolve_placeholder(&material.environment["TOKEN"]),
            Some("synthetic-credential-not-for-guest")
        );
        let generation = proxy.engine.current_generation();
        proxy
            .apply(1, &config, &provider)
            .expect("unchanged snapshot");
        assert_eq!(proxy.engine.current_generation(), generation);
        let (narrow, narrow_provider) = snapshots("/usr/local/bin/system-agent");
        assert!(
            proxy.apply(2, &narrow, &narrow_provider).is_err(),
            "VM cannot claim binary identity"
        );
        assert!(proxy.engine.fail_closed_reason().is_some());
        assert!(
            proxy
                .credentials
                .resolver_for_endpoint("93.184.216.34", 443, "/chat")
                .is_none()
        );
        assert!(
            proxy.apply(1, &config, &provider).is_err(),
            "stale grant cannot repair a rejected generation"
        );
        proxy
            .apply(3, &config, &provider)
            .expect("repair gateway revision with fresh mediation generation");
        proxy.revoke("lease expired").expect("revoke");
        assert!(
            proxy.apply(3, &config, &provider).is_err(),
            "revocation retains the high-water mark"
        );
        proxy.apply(4, &config, &provider).expect("new lease");
        guard.live.store(false, Ordering::Release);
        assert!(proxy.apply(5, &config, &provider).is_err());
    }

    #[tokio::test]
    async fn every_dial_checks_external_guard_and_revoke_closes_pending_connections() {
        let (proxy, guard, _directory, address) = start().await;
        let (config, provider) = snapshots("/**");
        proxy.apply(4, &config, &provider).expect("paired snapshot");
        let mut request = tokio::net::TcpStream::connect(address)
            .await
            .expect("proxy connection");
        request
            .write_all(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: 93.184.216.34:443\r\n\r\n")
            .await
            .expect("request");
        let mut bytes = [0; 64];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), request.read(&mut bytes))
            .await
            .expect("bounded refusal");
        assert!(
            guard.checked.load(Ordering::Acquire),
            "guard consulted before upstream dial"
        );
        let mut pending = tokio::net::TcpStream::connect(address)
            .await
            .expect("pending connection");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while proxy.active_connections() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pending connection accepted");
        proxy.revoke("lease expired").expect("revoke");
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), pending.read(&mut bytes))
                .await
                .expect("pending connection closed")
                .expect("EOF"),
            0
        );
    }
}
