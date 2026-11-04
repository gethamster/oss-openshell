// SPDX-FileCopyrightText: Copyright (c) 2026 Hamster
// SPDX-License-Identifier: Apache-2.0

//! Opt-in hosted billing at the trusted Kubernetes allocation boundary.
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client, api::DynamicObject};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    time::Duration,
};

type Result<T> = std::result::Result<T, String>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoint: String,
    token_file: PathBuf,
    outbox: PathBuf,
    workspaces: BTreeMap<String, String>,
}
struct Billing {
    config: Config,
    token: String,
    http: reqwest::Client,
}
impl Billing {
    fn load() -> Result<Option<Self>> {
        let Some(path) = std::env::var_os("OPENSHELL_BILLING_CONFIG") else {
            return Ok(None);
        };
        let load = || -> std::result::Result<Self, Box<dyn std::error::Error>> {
            let config: Config = serde_json::from_slice(&fs::read(path)?)?;
            let url = reqwest::Url::parse(&config.endpoint)?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !config.outbox.is_absolute()
            {
                return Err("invalid hosted billing configuration".into());
            }
            let meta = fs::symlink_metadata(&config.token_file)?;
            if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 || meta.len() > 256 {
                return Err("unsafe hosted billing authority".into());
            }
            let token = fs::read_to_string(&config.token_file)?.trim().to_owned();
            if token.len() < 32 {
                return Err("invalid billing authority".into());
            }
            fs::create_dir_all(&config.outbox)?;
            fs::set_permissions(&config.outbox, fs::Permissions::from_mode(0o700))?;
            let http = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?;
            Ok(Self {
                config,
                token,
                http,
            })
        };
        load()
            .map(Some)
            .map_err(|_| "hosted billing configuration unavailable".into())
    }
    fn path(&self, generation: &str, extension: &str) -> PathBuf {
        self.config
            .outbox
            .join(format!("{}.{extension}", identity(generation)))
    }
    fn save(&self, generation: &str, extension: &str, value: &Value) -> Result<()> {
        let temporary = self
            .config
            .outbox
            .join(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let save = || -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&serde_json::to_vec(value)?)?;
            file.sync_all()?;
            fs::rename(&temporary, self.path(generation, extension))?;
            fs::File::open(&self.config.outbox)?.sync_all()
        };
        save().map_err(|_| "billing evidence could not be persisted".into())
    }
    async fn post(&self, path: &str, value: &Value) -> Result<Value> {
        let response = self
            .http
            .post(format!(
                "{}{path}",
                self.config.endpoint.trim_end_matches('/')
            ))
            .bearer_auth(&self.token)
            .json(value)
            .send()
            .await
            .map_err(|_| "billing authority unavailable")?;
        if !response.status().is_success() {
            return Err("billing admission or receipt rejected".into());
        }
        response
            .json()
            .await
            .map_err(|_| "invalid billing acknowledgement".into())
    }
}
fn identity(generation: &str) -> String {
    let hash = Sha256::digest(generation.as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash[..16]);
    uuid::Uuid::from_bytes(bytes).to_string()
}
fn capacity(spec: &Value) -> Result<(i64, i64)> {
    let containers = spec["containers"]
        .as_array()
        .ok_or("missing allocated containers")?;
    let read = |container: &Value| -> Result<(i64, i64)> {
        let req = &container["resources"]["requests"];
        let cpu = req["cpu"].as_str().ok_or("missing CPU request")?;
        let cpu = if let Some(v) = cpu.strip_suffix('m') {
            v.parse().map_err(|_| "invalid CPU request")?
        } else {
            cpu.parse::<i64>()
                .map_err(|_| "invalid CPU request")?
                .checked_mul(1000)
                .ok_or("CPU overflow")?
        };
        let memory = req["memory"].as_str().ok_or("missing memory request")?;
        let (value, scale) = memory.strip_suffix("Gi").map_or_else(
            || {
                memory.strip_suffix("Mi").map_or_else(
                    || {
                        memory
                            .strip_suffix("Ki")
                            .map_or((memory, 1), |v| (v, 1_i64 << 10))
                    },
                    |v| (v, 1_i64 << 20),
                )
            },
            |v| (v, 1_i64 << 30),
        );
        let memory = value
            .parse::<i64>()
            .map_err(|_| "invalid memory request")?
            .checked_mul(scale)
            .ok_or("memory overflow")?;
        if cpu <= 0 || memory <= 0 {
            return Err("invalid allocation".into());
        }
        Ok((cpu, memory))
    };
    let (mut cpu, mut memory) = (0_i64, 0_i64);
    for container in containers {
        let (c, m) = read(container)?;
        cpu = cpu.checked_add(c).ok_or("CPU overflow")?;
        memory = memory.checked_add(m).ok_or("memory overflow")?;
    }
    if let Some(init) = spec["initContainers"].as_array() {
        for container in init {
            let (c, m) = read(container)?;
            cpu = cpu.max(c);
            memory = memory.max(m);
        }
    }
    Ok((cpu, memory))
}

pub async fn reserve(workspace: &str, sandbox: &str, generation: &str, spec: &Value) -> Result<()> {
    let Some(billing) = Billing::load()? else {
        return Ok(());
    };
    let Some(resource) = billing.config.workspaces.get(workspace) else {
        return Ok(());
    };
    let (cpu, memory) = capacity(spec)?;
    let value = json!({"resourceId":resource,"generation":identity(generation),"sandboxId":sandbox,"cpuMillis":cpu,"memoryBytes":memory});
    let result=billing.post("/api/internal/billing/sandbox-reservations",&json!({"resourceId":resource,"generation":identity(generation),"cpuMillis":cpu,"memoryBytes":memory})).await?;
    if result["enrolled"] == true {
        let mut marker = value;
        marker["runtimeGeneration"] = json!(generation);
        billing.save(generation, "enrolled", &marker)?;
    }
    Ok(())
}

pub async fn observe(client: Client, object: &DynamicObject) -> Result<()> {
    let Some(billing) = Billing::load()? else {
        return Ok(());
    };
    let workspace = object
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get("openshell.ai/sandbox-workspace"));
    if workspace.is_none_or(|workspace| !billing.config.workspaces.contains_key(workspace)) {
        return Ok(());
    }
    let annotations = object
        .metadata
        .annotations
        .as_ref()
        .ok_or("missing runtime annotations")?;
    let Some(generation) = annotations.get("openshell.ai/sandbox-runtime-generation") else {
        return Ok(());
    };
    if billing.path(generation, "settled").exists() {
        return Err("a released generation requires a fresh start".into());
    }
    let path = billing.path(generation, "enrolled");
    if !path.exists() {
        return Ok(());
    }
    let mut value: Value =
        serde_json::from_slice(&fs::read(path).map_err(|_| "missing billing intent")?)
            .map_err(|_| "invalid billing intent")?;
    if let Some(fields) = value.as_object_mut() {
        fields.retain(|key, _| {
            [
                "resourceId",
                "generation",
                "sandboxId",
                "cpuMillis",
                "memoryBytes",
            ]
            .contains(&key.as_str())
        });
    }
    let namespace = object
        .metadata
        .namespace
        .as_deref()
        .ok_or("missing namespace")?;
    let pod_name = annotations
        .get("agents.x-k8s.io/pod-name")
        .map(String::as_str)
        .or(object.metadata.name.as_deref())
        .ok_or("missing workload name")?;
    let pod = Api::<Pod>::namespaced(client, namespace)
        .get_opt(pod_name)
        .await
        .map_err(|_| "allocation observation unavailable")?;
    let Some(pod) = pod else {
        return release(generation).await;
    };
    if !pod
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners.iter().any(|owner| {
                Some(&owner.uid) == object.metadata.uid.as_ref() && owner.controller == Some(true)
            })
        })
    {
        return Err("allocation owner differs".into());
    }
    let Some(at) = pod
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| {
            cs.iter()
                .find(|c| c.type_ == "PodScheduled" && c.status == "True")
        })
        .and_then(|c| c.last_transition_time.as_ref())
    else {
        return Ok(());
    };
    let mut marker = value.clone();
    marker["runtimeGeneration"] = json!(generation);
    marker["namespace"] = json!(namespace);
    marker["podName"] = json!(pod_name);
    marker["podUid"] = json!(pod.metadata.uid);
    billing.save(generation, "enrolled", &marker)?;
    let spec = serde_json::to_value(pod.spec).map_err(|_| "invalid workload spec")?;
    let (cpu, memory) = capacity(&spec)?;
    if value["cpuMillis"] != cpu || value["memoryBytes"] != memory {
        return Err("allocation differs from admitted capacity".into());
    }
    value["allocatedAt"] = json!(at.0.to_rfc3339());
    value["observedAt"] = json!(k8s_openapi::chrono::Utc::now().to_rfc3339());
    value["releasedAt"] = Value::Null;
    billing.save(generation, "json", &value)?;
    billing
        .post("/api/internal/billing/sandboxes", &value)
        .await?;
    billing.post("/api/internal/billing/sandbox-reservations",&json!({"resourceId":value["resourceId"],"generation":value["generation"],"cpuMillis":cpu,"memoryBytes":memory})).await?;
    Ok(())
}
pub async fn release(generation: &str) -> Result<()> {
    let Some(billing) = Billing::load()? else {
        return Ok(());
    };
    let path = billing.path(generation, "json");
    if !path.exists() {
        return Ok(());
    }
    let mut value: Value = serde_json::from_slice(&fs::read(&path).map_err(|_| "missing receipt")?)
        .map_err(|_| "invalid receipt")?;
    if value["releasedAt"].is_null() {
        let now = json!(k8s_openapi::chrono::Utc::now().to_rfc3339());
        value["releasedAt"] = now.clone();
        value["observedAt"] = now;
        billing.save(generation, "json", &value)?;
    }
    billing
        .post("/api/internal/billing/sandboxes", &value)
        .await?;
    fs::rename(path, billing.path(generation, "settled"))
        .map_err(|_| "receipt acknowledgement could not be retained")?;
    Ok(())
}

/// Drain terminal receipts even after the Sandbox resource has been deleted.
pub async fn reconcile_missing(client: Client) -> Result<()> {
    let Some(billing) = Billing::load()? else {
        return Ok(());
    };
    for entry in fs::read_dir(&billing.config.outbox)
        .map_err(|_| "billing inventory unavailable")?
        .filter(|entry| {
            entry.is_err()
                || entry.as_ref().is_ok_and(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|ext| ext == "enrolled")
                        && entry.path().with_extension("json").exists()
                })
        })
        .take(1000)
    {
        let path = entry.map_err(|_| "billing inventory unavailable")?.path();
        if path.extension().is_none_or(|value| value != "enrolled") {
            continue;
        }
        let marker: Value =
            serde_json::from_slice(&fs::read(&path).map_err(|_| "billing intent unavailable")?)
                .map_err(|_| "invalid billing intent")?;
        let Some(generation) = marker["runtimeGeneration"].as_str() else {
            continue;
        };
        if billing.path(generation, "settled").exists()
            || !billing.path(generation, "json").exists()
        {
            continue;
        }
        let (Some(namespace), Some(name), Some(uid)) = (
            marker["namespace"].as_str(),
            marker["podName"].as_str(),
            marker["podUid"].as_str(),
        ) else {
            continue;
        };
        let pod = Api::<Pod>::namespaced(client.clone(), namespace)
            .get_opt(name)
            .await
            .map_err(|_| "resource release remains unknown")?;
        if pod
            .as_ref()
            .is_none_or(|pod| pod.metadata.uid.as_deref() != Some(uid))
        {
            release(generation).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_uses_allocations_and_the_largest_init_phase() {
        let spec = json!({"containers":[{"resources":{"requests":{"cpu":"2","memory":"4Gi"}}},{"resources":{"requests":{"cpu":"100m","memory":"128Mi"}}}],"initContainers":[{"resources":{"requests":{"cpu":"4","memory":"8Gi"}}}]});
        assert_eq!(capacity(&spec).expect("resources"), (4000, 8_i64 << 30));
        assert!(capacity(&json!({"containers":[{}]})).is_err());
        let id = identity("opaque-driver-generation");
        assert_eq!(id, identity("opaque-driver-generation"));
        assert_ne!(id, identity("next-generation"));
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }
}
