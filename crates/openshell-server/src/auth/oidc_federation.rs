// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registry-backed issuer federation. Untrusted claims select an existing trust
//! registration; only that registration can authorize discovery or key fetching.
use super::{AuthFailureReason, AuthRejection, Identity, JwksCache, fetch_bounded_json, reject};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openshell_core::OidcConfig;
use reqwest::Client;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OnceCell, RwLock};
use tonic::Status;
use tracing::warn;

const REGISTRY_TTL: Duration = Duration::from_secs(30);
const MAX_TOKEN: usize = 32 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    issuer: String,
    audience: String,
    subjects: HashSet<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    issuers: Vec<Registration>,
}
#[derive(Deserialize)]
struct Selector {
    iss: String,
    sub: String,
    iat: u64,
    exp: u64,
    jti: String,
}
struct Loaded {
    /// When the read of this copy started.
    at: Instant,
    registrations: HashMap<String, Registration>,
}
impl Loaded {
    fn admitted(&self, issuer: &str, subject: &str) -> Option<Registration> {
        self.registrations
            .get(issuer)
            .filter(|r| r.subjects.contains(subject))
            .cloned()
    }
}
type Verifier = Arc<OnceCell<Arc<JwksCache>>>;

/// One copy of the registry and one key cache for each registered issuer.
/// The gateway's startup cache owns it, so every connection shares it.
pub(super) struct Federation {
    config: OidcConfig,
    http: Client,
    /// The copy requests decide from. A request it admits never waits for a
    /// registry read while the copy is within `REGISTRY_TTL`.
    loaded: RwLock<Option<Arc<Loaded>>>,
    /// Lets one registry read run at a time, and holds when the latest read
    /// that failed started, so requests that waited for it share its result.
    reading: Mutex<Option<Instant>>,
    verifiers: Mutex<HashMap<(String, String), Verifier>>,
}
impl Federation {
    pub(super) fn new(config: OidcConfig, http: Client) -> Self {
        Self {
            config,
            http,
            loaded: RwLock::new(None),
            reading: Mutex::new(None),
            verifiers: Mutex::new(HashMap::new()),
        }
    }

    /// The copy of the registry, while it is within `REGISTRY_TTL`.
    async fn current(&self) -> Option<Arc<Loaded>> {
        let loaded = self.loaded.read().await;
        loaded
            .as_ref()
            .filter(|copy| copy.at.elapsed() < REGISTRY_TTL)
            .cloned()
    }

    /// Read the registry, and drop the key caches of issuers it no longer lists.
    async fn load(&self, at: Instant) -> Result<Loaded, AuthRejection> {
        let url = self
            .config
            .federation_registry_url
            .as_deref()
            .ok_or_else(invalid)?;
        let url = url::Url::parse(url).map_err(|_| unavailable())?;
        let document: Registry =
            fetch_bounded_json(&self.http, &url, "federation registry", 1024 * 1024)
                .await
                .map_err(|error| {
                    warn!(error = %error, "Federation registry could not be read");
                    unavailable()
                })?;
        if document.version != 1 || document.issuers.len() > 1000 {
            return Err(unavailable());
        }
        let mut registrations = HashMap::new();
        let mut count = 0usize;
        for registration in document.issuers {
            count += registration.subjects.len();
            if count > 10_000
                || registration.audience.is_empty()
                || registration.audience.len() > 2048
                || !identifier(&registration.issuer)
                || registration.subjects.iter().any(|v| !identifier(v))
            {
                return Err(unavailable());
            }
            let key = registration.issuer.clone();
            if registrations.insert(key, registration).is_some() {
                return Err(unavailable());
            }
        }
        self.verifiers.lock().await.retain(|(issuer, audience), _| {
            registrations
                .get(issuer)
                .is_some_and(|r| r.audience == *audience)
        });
        Ok(Loaded { at, registrations })
    }

    /// The registration that admits `subject`, for a request that arrived at `asked`.
    ///
    /// Every connection shares the copy, so it can be older than a
    /// registration the caller was just given. A caller the copy does not
    /// admit is therefore decided by a read that started after its request
    /// arrived: its own, or one another request made while it waited.
    async fn registration(
        &self,
        issuer: &str,
        subject: &str,
        asked: Instant,
    ) -> Result<Registration, AuthRejection> {
        let admitted = |copy: &Arc<Loaded>| copy.admitted(issuer, subject);
        if let Some(registration) = self.current().await.as_ref().and_then(admitted) {
            return Ok(registration);
        }
        let mut failed = self.reading.lock().await;
        if let Some(copy) = self.current().await {
            let registration = admitted(&copy);
            if registration.is_some() || copy.at >= asked {
                return registration.ok_or_else(invalid);
            }
        }
        if failed.is_some_and(|at| at >= asked) {
            return Err(unavailable());
        }
        let started = Instant::now();
        match self.load(started).await {
            Ok(copy) => {
                let copy = Arc::new(copy);
                *self.loaded.write().await = Some(copy.clone());
                *failed = None;
                admitted(&copy).ok_or_else(invalid)
            }
            Err(rejection) => {
                // The previous copy stays as it is: within its TTL it still
                // admits the callers it lists, and past it nothing is admitted.
                *failed = Some(started);
                Err(rejection)
            }
        }
    }

    pub(super) async fn authenticate(&self, token: &str) -> Result<Identity, AuthRejection> {
        let asked = Instant::now();
        if token.len() > MAX_TOKEN {
            return Err(invalid());
        }
        let mut parts = token.split('.');
        let (_, Some(payload), Some(_), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        let selector: Selector =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        let registration = self
            .registration(&selector.iss, &selector.sub, asked)
            .await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| unavailable())?
            .as_secs();
        if selector.iat > now
            || selector.exp <= now
            || selector.exp <= selector.iat
            || selector.exp - selector.iat > 300
            || !identifier(&selector.jti)
            || jsonwebtoken::decode_header(token)
                .map_err(|_| invalid())?
                .alg
                != jsonwebtoken::Algorithm::EdDSA
        {
            return Err(invalid());
        }
        let verifier = self
            .verifiers
            .lock()
            .await
            .entry((registration.issuer.clone(), registration.audience.clone()))
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();
        let cache = verifier
            .get_or_try_init(|| async {
                let config = OidcConfig {
                    issuer: registration.issuer.clone(),
                    audience: registration.audience.clone(),
                    federation_registry_url: None,
                    jwks_ttl_secs: 30,
                    jwks_allowed_origins: Vec::new(),
                    ..self.config.clone()
                };
                JwksCache::new_with_client(&config, self.http.clone())
                    .await
                    .map(Arc::new)
                    .map_err(|error| {
                        warn!(
                            issuer = %registration.issuer,
                            error = %error,
                            "Keys of a registered issuer could not be loaded"
                        );
                        unavailable()
                    })
            })
            .await?;
        let mut identity = cache.validate_token(token).await?;
        identity.subject =
            serde_json::to_string(&[selector.iss, identity.subject]).map_err(|_| invalid())?;
        identity.roles = vec![self.config.user_role.clone()];
        identity.scopes.clear();
        Ok(identity)
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}
fn invalid() -> AuthRejection {
    reject(
        AuthFailureReason::InvalidCredential,
        Status::unauthenticated("invalid federated identity"),
    )
}
fn unavailable() -> AuthRejection {
    reject(
        AuthFailureReason::IdentityProviderUnavailable,
        Status::unavailable("federation authority unavailable"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    struct Issuer {
        server: MockServer,
        key: jsonwebtoken::EncodingKey,
        x: String,
    }
    impl Issuer {
        async fn new() -> Self {
            crate::install_jsonwebtoken_crypto_provider();
            let server = MockServer::start().await;
            let pair = openshell_crypto::pki::generate_keypair_for(&rcgen::PKCS_ED25519).unwrap();
            let key =
                jsonwebtoken::EncodingKey::from_ed_pem(pair.serialize_pem().unwrap().as_bytes())
                    .unwrap();
            let spki = pair.public_key_der();
            let x = URL_SAFE_NO_PAD.encode(&spki[spki.len() - 32..]);
            let issuer = Self { server, key, x };
            issuer.serve().await;
            issuer
        }
        async fn serve(&self) {
            let server = &self.server;
            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    json!({"issuer":server.uri(),"jwks_uri":format!("{}/keys",server.uri())}),
                ))
                .mount(server)
                .await;
            Mock::given(method("GET")).and(path("/keys"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys":[{"kid":"key","kty":"OKP","crv":"Ed25519","x":self.x,"alg":"EdDSA"}]})))
                .mount(server).await;
        }
        fn token(&self, subject: &str) -> String {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
            header.kid = Some("key".into());
            openshell_crypto::jwt::encode(&header, &json!({"iss":self.server.uri(),"sub":subject,"aud":"api","iat":now,"exp":now+300,"jti":"execution","roles":["openshell-admin"]}), &self.key).unwrap()
        }
    }
    /// The gateway's own cache, as its startup builds it once.
    async fn cache(registry: &MockServer, issuer: &Issuer) -> Arc<JwksCache> {
        let config = OidcConfig {
            issuer: issuer.server.uri(),
            audience: "api".into(),
            federation_registry_url: Some(format!("{}/registry", registry.uri())),
            dangerously_allow_insecure_http: true,
            jwks_allowed_origins: vec![],
            jwks_ttl_secs: 30,
            roles_claim: "roles".into(),
            admin_role: "openshell-admin".into(),
            user_role: "openshell-user".into(),
            scopes_claim: String::new(),
        };
        Arc::new(JwksCache::new(&config).await.unwrap())
    }
    async fn registrations(server: &MockServer, issuers: Vec<serde_json::Value>) {
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/registry"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"version":1,"issuers":issuers})),
            )
            .mount(server)
            .await;
    }
    /// Age the registry copy past its TTL.
    async fn expire(federation: &Federation) {
        let mut loaded = federation.loaded.write().await;
        let copy = loaded.take().unwrap();
        *loaded = Some(Arc::new(Loaded {
            at: copy.at.checked_sub(REGISTRY_TTL).unwrap(),
            registrations: copy.registrations.clone(),
        }));
    }
    async fn hits(server: &MockServer, route: &str) -> usize {
        let requests = server.received_requests().await.unwrap();
        requests.iter().filter(|r| r.url.path() == route).count()
    }
    fn bearer(token: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers
    }
    #[tokio::test]
    async fn connections_share_one_registry_read_discovery_and_key_fetch() {
        use crate::auth::authenticator::{Authentication, Authenticator};
        // The gateway builds one authenticator for each accepted connection.
        let home = Issuer::new().await;
        let issuer = Issuer::new().await;
        let registry = MockServer::start().await;
        registrations(
            &registry,
            vec![json!({"issuer":issuer.server.uri(),"audience":"api","subjects":["agent"]})],
        )
        .await;
        let cache = cache(&registry, &home).await;
        let token = issuer.token("agent");
        for _ in 0..20 {
            let connection = crate::auth::oidc::OidcAuthenticator::new(cache.clone());
            for _ in 0..3 {
                let accepted = connection
                    .authenticate(&bearer(&token), "/openshell.v1.OpenShell/GetSandbox")
                    .await
                    .expect("an admitted subject with a valid token is accepted");
                assert!(matches!(accepted, Authentication::Accepted(_)));
            }
        }
        assert_eq!(hits(&registry, "/registry").await, 1);
        assert_eq!(
            hits(&issuer.server, "/.well-known/openid-configuration").await,
            1
        );
        assert_eq!(hits(&issuer.server, "/keys").await, 1);
    }
    #[tokio::test]
    async fn new_registration_applies_without_waiting_for_the_registry_ttl() {
        let issuer = Issuer::new().await;
        let registry = MockServer::start().await;
        let admitted = |subjects: &[&str]| {
            vec![json!({"issuer":issuer.server.uri(),"audience":"api","subjects":subjects})]
        };
        registrations(&registry, admitted(&["agent"])).await;
        let cache = cache(&registry, &issuer).await;
        let federation = cache.federation.as_ref().unwrap();
        assert!(
            federation
                .authenticate(&issuer.token("agent"))
                .await
                .is_ok()
        );

        registrations(&registry, admitted(&["agent", "owner"])).await;
        assert!(
            federation
                .authenticate(&issuer.token("owner"))
                .await
                .is_ok()
        );
        assert_eq!(
            federation
                .authenticate(&issuer.token("not-enrolled"))
                .await
                .unwrap_err()
                .reason,
            AuthFailureReason::InvalidCredential
        );
        // One read for the new subject and one for the unknown one. Subjects
        // the copy admits never cause a read inside the registry TTL.
        assert!(
            federation
                .authenticate(&issuer.token("agent"))
                .await
                .is_ok()
        );
        assert_eq!(hits(&registry, "/registry").await, 2);
    }
    #[tokio::test]
    async fn failed_registry_read_for_an_unknown_subject_keeps_admitted_subjects() {
        let issuer = Issuer::new().await;
        let registry = MockServer::start().await;
        registrations(
            &registry,
            vec![json!({"issuer":issuer.server.uri(),"audience":"api","subjects":["agent"]})],
        )
        .await;
        let cache = cache(&registry, &issuer).await;
        let federation = cache.federation.as_ref().unwrap();
        let token = issuer.token("agent");
        assert!(federation.authenticate(&token).await.is_ok());

        registry.reset().await;
        assert_eq!(
            federation
                .authenticate(&issuer.token("not-enrolled"))
                .await
                .unwrap_err()
                .reason,
            AuthFailureReason::IdentityProviderUnavailable
        );
        // The copy is within its TTL, so the subject it admits needs no read.
        assert!(federation.authenticate(&token).await.is_ok());
        assert_eq!(hits(&registry, "/registry").await, 1);

        // Past the TTL the same outage admits nobody.
        expire(federation).await;
        assert_eq!(
            federation.authenticate(&token).await.unwrap_err().reason,
            AuthFailureReason::IdentityProviderUnavailable
        );
    }
    #[tokio::test]
    async fn issuer_without_an_answer_refuses_until_its_keys_are_loaded() {
        let home = Issuer::new().await;
        let issuer = Issuer::new().await;
        let registry = MockServer::start().await;
        registrations(
            &registry,
            vec![json!({"issuer":issuer.server.uri(),"audience":"api","subjects":["agent"]})],
        )
        .await;
        let cache = cache(&registry, &home).await;
        let federation = cache.federation.as_ref().unwrap();
        let token = issuer.token("agent");

        issuer.server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&issuer.server)
            .await;
        assert_eq!(
            federation.authenticate(&token).await.unwrap_err().reason,
            AuthFailureReason::IdentityProviderUnavailable
        );

        issuer.server.reset().await;
        issuer.serve().await;
        assert!(federation.authenticate(&token).await.is_ok());
    }
    #[tokio::test]
    async fn issuer_scoping_prevents_subject_collisions_and_signer_substitution() {
        let a = Issuer::new().await;
        let b = Issuer::new().await;
        let registry = MockServer::start().await;
        registrations(
            &registry,
            vec![
                json!({"issuer":a.server.uri(),"audience":"api","subjects":["same-subject"]}),
                json!({"issuer":b.server.uri(),"audience":"api","subjects":["same-subject"]}),
            ],
        )
        .await;
        let cache = cache(&registry, &a).await;
        let federation = cache.federation.as_ref().unwrap();
        let left = federation
            .authenticate(&a.token("same-subject"))
            .await
            .unwrap();
        let right = federation
            .authenticate(&b.token("same-subject"))
            .await
            .unwrap();
        assert_ne!(left.subject, right.subject);
        assert_eq!(
            left.subject,
            serde_json::to_string(&[a.server.uri(), "same-subject".to_string()]).unwrap()
        );
        assert_eq!(left.roles, ["openshell-user"]);
        assert!(left.scopes.is_empty());
        assert!(
            federation
                .authenticate(&a.token("not-enrolled"))
                .await
                .is_err()
        );
        let token = a.token("same-subject");
        let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
        let mut claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[1]).unwrap()).unwrap();
        claims["iss"] = b.server.uri().into();
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        assert!(federation.authenticate(&parts.join(".")).await.is_err());
    }
    #[tokio::test]
    async fn registry_removal_and_outage_do_not_reuse_stale_authority() {
        let issuer = Issuer::new().await;
        let registry = MockServer::start().await;
        registrations(
            &registry,
            vec![json!({"issuer":issuer.server.uri(),"audience":"api","subjects":["agent"]})],
        )
        .await;
        let cache = cache(&registry, &issuer).await;
        let federation = cache.federation.as_ref().unwrap();
        let token = issuer.token("agent");
        assert!(federation.authenticate(&token).await.is_ok());
        expire(federation).await;
        registrations(&registry, vec![]).await;
        assert!(federation.authenticate(&token).await.is_err());
        expire(federation).await;
        registry.reset().await;
        assert_eq!(
            federation.authenticate(&token).await.unwrap_err().reason,
            AuthFailureReason::IdentityProviderUnavailable
        );
    }
}
