// SPDX-FileCopyrightText: Copyright (c) 2026 Hamster
// SPDX-License-Identifier: Apache-2.0

//! Cursor renews CLI credentials by re-exchanging the user API key. Neither
//! that key nor the exchange response is returned to a sandbox.

use super::{
    DEFAULT_MAX_LIFETIME_SECONDS, MintedCredential, OAuthGrantKind, RefreshFailure,
    StoredProviderCredentialRefreshState, classify_oauth_token_error, current_time_ms,
    max_lifetime_seconds, read_bounded_oauth_error_body, required_material,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use tonic::Status;

const EXCHANGE_URL: &str = "https://api2.cursor.sh/auth/exchange_user_api_key";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeResponse {
    access_token: String,
    refresh_token: String,
}

fn invalid_response() -> RefreshFailure {
    RefreshFailure::investigate(
        Status::failed_precondition("Cursor returned an unusable credential response"),
        "cursor_invalid_success_response",
    )
}

fn unavailable() -> RefreshFailure {
    // Repeating an API-key exchange does not consume a rotating refresh token.
    RefreshFailure::retryable(
        Status::unavailable("Cursor credential exchange is unavailable"),
        "cursor_exchange_unavailable",
    )
}

fn endpoint(value: &str) -> Result<reqwest::Url, Status> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| Status::invalid_argument("invalid Cursor token_url"))?;
    let local_test = url.scheme() == "http"
        && url.host_str().is_some_and(super::is_loopback_host)
        && url.path() == "/auth/exchange_user_api_key"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if value != EXCHANGE_URL && !local_test {
        return Err(Status::invalid_argument(
            "Cursor token_url must use its API-key exchange endpoint",
        ));
    }
    Ok(url)
}

pub(super) async fn mint(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, RefreshFailure> {
    let url = endpoint(&state.token_url)?;
    let key = required_material(&state.material, "api_key")?;
    openshell_crypto::tls::ensure_default_provider();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| unavailable())?;
    let mut response = client
        .post(url)
        .bearer_auth(key)
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|_| unavailable())?;
    let status = response.status();
    if !status.is_success() {
        let body = read_bounded_oauth_error_body(response).await;
        if matches!(status.as_u16(), 401 | 403) {
            return Err(RefreshFailure::reauthorize(
                Status::unauthenticated("Cursor API key was rejected; reconnect the provider"),
                "cursor_api_key_rejected",
                None,
            ));
        }
        return Err(classify_oauth_token_error(
            status,
            &body,
            OAuthGrantKind::UserRefreshToken,
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(invalid_response());
        }
        bytes.extend_from_slice(&chunk);
    }
    let response: ExchangeResponse =
        serde_json::from_slice(&bytes).map_err(|_| invalid_response())?;
    if response.access_token.trim().is_empty() || response.refresh_token.trim().is_empty() {
        return Err(invalid_response());
    }
    let now = current_time_ms();
    let expiration = openshell_core::jwt::parse_exp_secs(&response.access_token)
        .and_then(|seconds| seconds.checked_mul(1000))
        .filter(|expiration| *expiration > now)
        .ok_or_else(invalid_response)?;
    let cap = match max_lifetime_seconds(state) {
        seconds if seconds > 0 => seconds,
        _ => DEFAULT_MAX_LIFETIME_SECONDS,
    };
    Ok(MintedCredential {
        access_token: response.access_token,
        expires_at_ms: expiration.min(now.saturating_add(cap.saturating_mul(1000))),
        // The CLI renews with the API key, not the returned refresh token.
        refresh_token: None,
        additional_credentials: HashMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use openshell_core::proto::ProviderCredentialRefreshRecoveryAction;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    fn token(expiration: i64) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({"exp":expiration}).to_string());
        format!("e30.{payload}.test-signature")
    }

    fn state(server: &MockServer) -> StoredProviderCredentialRefreshState {
        StoredProviderCredentialRefreshState {
            token_url: format!("{}/auth/exchange_user_api_key", server.uri()),
            material: HashMap::from([("api_key".into(), "private-test-key".into())]),
            max_lifetime: Some(prost_types::Duration {
                seconds: 3600,
                nanos: 0,
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn cursor_exchange_uses_private_bearer_and_bounds_token_lifetime() {
        let server = MockServer::start().await;
        let access = token(current_time_ms() / 1000 + 7200);
        Mock::given(method("POST"))
            .and(path("/auth/exchange_user_api_key"))
            .and(header("authorization", "Bearer private-test-key"))
            .and(body_json(serde_json::json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accessToken":access,"refreshToken":"unused-private-refresh-token"
            })))
            .expect(2)
            .mount(&server)
            .await;
        for _ in 0..2 {
            let now = current_time_ms();
            let minted = mint(&state(&server)).await.expect("Cursor exchange");
            assert_eq!(minted.access_token, access);
            assert!(minted.expires_at_ms <= current_time_ms() + 3_600_000);
            assert!(minted.expires_at_ms >= now + 3_590_000);
            assert!(minted.refresh_token.is_none());
            assert!(minted.additional_credentials.is_empty());
        }
    }

    #[tokio::test]
    async fn cursor_rejects_incomplete_expired_or_unbounded_response_without_secret_errors() {
        let server = MockServer::start().await;
        for body in [
            serde_json::json!({"accessToken":"private-token"}),
            serde_json::json!({"accessToken":"private-token","refreshToken":"private-refresh"}),
            serde_json::json!({"accessToken":token(current_time_ms()/1000-10),"refreshToken":"private-refresh"}),
            serde_json::json!({"accessToken":"","refreshToken":"private-refresh"}),
            serde_json::json!({"accessToken":"x".repeat(MAX_RESPONSE_BYTES),"refreshToken":"private-refresh"}),
        ] {
            server.reset().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
            let failure = mint(&state(&server))
                .await
                .expect_err("invalid token response");
            assert_eq!(failure.failure_code, "cursor_invalid_success_response");
            assert!(!failure.status.message().contains("private"));
        }
    }

    #[tokio::test]
    async fn cursor_classifies_rejected_key_and_transient_or_uncertain_exchanges() {
        let server = MockServer::start().await;
        for (status, code, action) in [
            (
                401,
                "cursor_api_key_rejected",
                ProviderCredentialRefreshRecoveryAction::Reauthorize,
            ),
            (
                403,
                "cursor_api_key_rejected",
                ProviderCredentialRefreshRecoveryAction::Reauthorize,
            ),
            (
                400,
                "oauth_invalid_grant",
                ProviderCredentialRefreshRecoveryAction::Reauthorize,
            ),
            (
                503,
                "oauth_token_endpoint_retryable",
                ProviderCredentialRefreshRecoveryAction::Retry,
            ),
        ] {
            server.reset().await;
            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_json(serde_json::json!({
                        "error":"invalid_grant","error_description":"private-test-key"
                    })),
                )
                .mount(&server)
                .await;
            let failure = mint(&state(&server)).await.expect_err("rejected exchange");
            assert_eq!(failure.failure_code, code);
            assert_eq!(failure.recovery_action, action);
            assert!(!failure.status.message().contains("private-test-key"));
        }
        let mut disconnected = state(&server);
        disconnected.token_url = "http://127.0.0.1:1/auth/exchange_user_api_key".into();
        let failure = mint(&disconnected).await.expect_err("connection failure");
        assert_eq!(failure.failure_code, "cursor_exchange_unavailable");
        assert_eq!(
            failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Retry
        );
    }

    #[test]
    fn cursor_pins_the_exchange_authority() {
        assert!(endpoint(EXCHANGE_URL).is_ok());
        for value in [
            "https://api2.cursor.sh.evil.test/auth/exchange_user_api_key",
            "https://api2.cursor.sh/auth/exchange_user_api_key?token=secret",
            "http://api2.cursor.sh/auth/exchange_user_api_key",
            "http://127.0.0.1/auth/other",
        ] {
            assert!(endpoint(value).is_err());
        }
    }

    #[tokio::test]
    async fn cursor_lost_exchange_response_is_retryable_without_consuming_a_refresh_token() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
            // Upstream accepted the API key, then the response stream was lost.
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{")
                .await
                .unwrap();
        });
        let mut request = StoredProviderCredentialRefreshState {
            token_url: format!("http://{address}/auth/exchange_user_api_key"),
            material: HashMap::from([("api_key".into(), "private-test-key".into())]),
            ..Default::default()
        };
        let failure = mint(&request).await.unwrap_err();
        server.await.unwrap();
        assert_eq!(failure.failure_code, "cursor_exchange_unavailable");
        assert_eq!(
            failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Retry
        );
        assert_eq!(
            request.material.remove("api_key").as_deref(),
            Some("private-test-key")
        );
        assert!(!failure.status.message().contains("private-test-key"));
    }
}
