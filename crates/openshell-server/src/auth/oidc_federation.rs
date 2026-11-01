// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registry-backed issuer federation. Untrusted claims select an existing trust
//! registration; only that registration can authorize discovery or key fetching.
use super::{AuthFailureReason, AuthRejection, Identity, JwksCache, fetch_bounded_json, reject};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OnceCell};
use tonic::Status;

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
    at: Instant,
    registrations: HashMap<String, Registration>,
}
type Verifier = Arc<OnceCell<Arc<JwksCache>>>;

pub(super) struct Federation {
    base: Arc<JwksCache>,
    loaded: Mutex<Option<Loaded>>,
    verifiers: Mutex<HashMap<(String, String), Verifier>>,
}
impl Federation {
    pub(super) fn new(base: Arc<JwksCache>) -> Self {
        Self {
            base,
            loaded: Mutex::new(None),
            verifiers: Mutex::new(HashMap::new()),
        }
    }

    async fn registration(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Registration, AuthRejection> {
        let mut loaded = self.loaded.lock().await;
        if loaded
            .as_ref()
            .is_none_or(|value| value.at.elapsed() >= REGISTRY_TTL)
        {
            let url = self
                .base
                .config
                .federation_registry_url
                .as_deref()
                .ok_or_else(invalid)?;
            let url = url::Url::parse(url).map_err(|_| unavailable())?;
            let document: Registry =
                fetch_bounded_json(&self.base.http, &url, "federation registry", 1024 * 1024)
                    .await
                    .map_err(|_| unavailable())?;
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
            *loaded = Some(Loaded {
                at: Instant::now(),
                registrations,
            });
        }
        loaded
            .as_ref()
            .and_then(|value| value.registrations.get(issuer))
            .filter(|r| r.subjects.contains(subject))
            .cloned()
            .ok_or_else(invalid)
    }

    pub(super) async fn authenticate(&self, token: &str) -> Result<Identity, AuthRejection> {
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
        let registration = self.registration(&selector.iss, &selector.sub).await?;
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
                let mut config = self.base.config.clone();
                config.issuer = registration.issuer.clone();
                config.audience = registration.audience.clone();
                config.federation_registry_url = None;
                config.jwks_ttl_secs = 30;
                config.jwks_allowed_origins.clear();
                JwksCache::new_with_client(&config, self.base.http.clone())
                    .await
                    .map(Arc::new)
                    .map_err(|_| unavailable())
            })
            .await?;
        let mut identity = cache.validate_token(token).await?;
        identity.subject =
            serde_json::to_string(&[selector.iss, identity.subject]).map_err(|_| invalid())?;
        identity.roles = vec![self.base.config.user_role.clone()];
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
    use openshell_core::OidcConfig;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    struct Issuer {
        server: MockServer,
        key: jsonwebtoken::EncodingKey,
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
            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    json!({"issuer":server.uri(),"jwks_uri":format!("{}/keys",server.uri())}),
                ))
                .mount(&server)
                .await;
            Mock::given(method("GET")).and(path("/keys"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys":[{"kid":"key","kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(&spki[spki.len()-32..]),"alg":"EdDSA"}]})))
                .mount(&server).await;
            Self { server, key }
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
    async fn federation(registry: &MockServer, issuer: &Issuer) -> Federation {
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
        Federation::new(Arc::new(JwksCache::new(&config).await.unwrap()))
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
        let federation = federation(&registry, &a).await;
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
        let federation = federation(&registry, &issuer).await;
        let token = issuer.token("agent");
        assert!(federation.authenticate(&token).await.is_ok());
        federation.loaded.lock().await.as_mut().unwrap().at -= REGISTRY_TTL;
        registrations(&registry, vec![]).await;
        assert!(federation.authenticate(&token).await.is_err());
        federation.loaded.lock().await.as_mut().unwrap().at -= REGISTRY_TTL;
        registry.reset().await;
        assert_eq!(
            federation.authenticate(&token).await.unwrap_err().reason,
            AuthFailureReason::IdentityProviderUnavailable
        );
    }
}
