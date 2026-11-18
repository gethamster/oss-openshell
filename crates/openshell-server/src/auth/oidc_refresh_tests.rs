// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! When the JWKS cache asks the issuer, and what it decides when the issuer
//! gives no answer.

use super::tests::{
    TEST_AUDIENCE, TEST_KID, TEST_RSA_KEY, cache_with_mock_issuer, claims_for, mint_rs256,
    mock_issuer_config, now_secs,
};
use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DISCOVERY: &str = "/.well-known/openid-configuration";
const JWKS: &str = "/jwks";
/// Windows short enough that a test can place the cache timestamps on either
/// side of them on a host that started a minute ago, and long enough that a
/// slow test run stays inside them.
const TTL: Duration = Duration::from_secs(20);
const LIMIT: Duration = Duration::from_secs(20);
const MARGIN: Duration = Duration::from_secs(1);

async fn hits(server: &MockServer, route: &str) -> usize {
    let requests = server.received_requests().await.unwrap();
    requests.iter().filter(|r| r.url.path() == route).count()
}

fn token(server: &MockServer, kid: &str) -> String {
    mint_rs256(
        &claims_for(&server.uri(), TEST_AUDIENCE, now_secs() + 3600),
        kid,
    )
}

fn before_now(age: Duration) -> Instant {
    Instant::now()
        .checked_sub(age)
        .expect("the host has been up for longer than the test's key age")
}

/// `cache` with the test windows, as if it last loaded its keys `age` ago.
async fn aged(cache: JwksCache, age: Duration) -> JwksCache {
    let cache = JwksCache {
        ttl: TTL,
        unanswered_limit: LIMIT,
        ..cache
    };
    *cache.last_refresh.write().await = before_now(age);
    *cache.last_nonempty_refresh.write().await = before_now(age);
    cache
}

/// Replace every reply of the issuer, and forget the requests it has seen.
async fn jwks_replies(server: &MockServer, reply: ResponseTemplate) {
    server.reset().await;
    Mock::given(method("GET"))
        .and(path(JWKS))
        .respond_with(reply)
        .mount(server)
        .await;
}

fn key_set(kids: &[&str]) -> ResponseTemplate {
    let keys: Vec<_> = kids
        .iter()
        .map(|kid| {
            serde_json::json!({
                "kid": kid,
                "kty": "RSA",
                "n": TEST_RSA_KEY.modulus_b64,
                "e": TEST_RSA_KEY.exponent_b64,
            })
        })
        .collect();
    ResponseTemplate::new(200).set_body_json(serde_json::json!({ "keys": keys }))
}

/// Undecided, and reported with the status a caller repeats a request for.
fn unavailable(rejection: &AuthRejection) -> bool {
    rejection.reason == AuthFailureReason::IdentityProviderUnavailable
        && rejection.status.code() == tonic::Code::Unavailable
}

#[tokio::test]
async fn verifications_within_the_ttl_ask_the_issuer_once() {
    let server = MockServer::start().await;
    let cache = cache_with_mock_issuer(&server).await;
    let token = token(&server, TEST_KID);

    for _ in 0..50 {
        cache
            .validate_token(&token)
            .await
            .expect("a valid token is accepted");
    }

    assert_eq!(hits(&server, DISCOVERY).await, 1);
    assert_eq!(hits(&server, JWKS).await, 1);
}

#[tokio::test]
async fn refresh_without_an_answer_decides_from_recent_keys() {
    let server = MockServer::start().await;
    let cache = aged(cache_with_mock_issuer(&server).await, TTL + MARGIN).await;
    let token = token(&server, TEST_KID);
    jwks_replies(&server, ResponseTemplate::new(503)).await;

    for _ in 0..5 {
        cache
            .validate_token(&token)
            .await
            .expect("recent keys decide while the issuer gives no answer");
    }

    // The issuer is asked once, then left alone until the retry interval ends.
    assert_eq!(hits(&server, JWKS).await, 1);
}

#[tokio::test]
async fn refresh_that_times_out_decides_from_recent_keys() {
    let server = MockServer::start().await;
    // Only the refresh uses the short timeout; the first load has the usual one.
    let http = Client::builder()
        .timeout(Duration::from_millis(250))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let cache = JwksCache {
        http,
        ..aged(cache_with_mock_issuer(&server).await, TTL + MARGIN).await
    };
    let token = token(&server, TEST_KID);
    jwks_replies(
        &server,
        key_set(&[TEST_KID]).set_delay(Duration::from_secs(5)),
    )
    .await;

    cache
        .validate_token(&token)
        .await
        .expect("recent keys decide when the issuer does not answer in time");
}

#[tokio::test]
async fn refresh_without_an_answer_refuses_past_the_limit() {
    let server = MockServer::start().await;
    let cache = aged(cache_with_mock_issuer(&server).await, TTL + LIMIT + MARGIN).await;
    let token = token(&server, TEST_KID);
    jwks_replies(&server, ResponseTemplate::new(503)).await;

    let rejection = cache
        .validate_token(&token)
        .await
        .expect_err("keys the issuer has not confirmed for too long decide nothing");
    assert!(unavailable(&rejection));
}

#[tokio::test]
async fn refresh_that_the_issuer_refuses_does_not_keep_cached_keys() {
    let server = MockServer::start().await;
    let cache = aged(cache_with_mock_issuer(&server).await, TTL + MARGIN).await;
    let token = token(&server, TEST_KID);
    jwks_replies(&server, ResponseTemplate::new(404)).await;

    let rejection = cache
        .validate_token(&token)
        .await
        .expect_err("an answer that refuses is not an outage");
    assert!(unavailable(&rejection));

    // No answer after a refusal does not bring the cached keys back.
    jwks_replies(&server, ResponseTemplate::new(503)).await;
    let rejection = cache
        .validate_token(&token)
        .await
        .expect_err("the issuer has refused since it last served its keys");
    assert!(unavailable(&rejection));

    // Only a served JWKS does.
    jwks_replies(&server, key_set(&[TEST_KID])).await;
    cache
        .validate_token(&token)
        .await
        .expect("the issuer served its keys again");
}

#[tokio::test]
async fn requests_wait_for_a_refresh_after_the_issuer_refused() {
    let server = MockServer::start().await;
    let cache = Arc::new(aged(cache_with_mock_issuer(&server).await, TTL + MARGIN).await);
    let token = token(&server, TEST_KID);
    jwks_replies(&server, ResponseTemplate::new(404)).await;
    cache.validate_token(&token).await.unwrap_err();

    jwks_replies(
        &server,
        ResponseTemplate::new(404).set_delay(Duration::from_millis(500)),
    )
    .await;
    let refreshing = tokio::spawn({
        let (cache, token) = (cache.clone(), token.clone());
        async move { cache.validate_token(&token).await }
    });
    while hits(&server, JWKS).await == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let rejection = cache
        .validate_token(&token)
        .await
        .expect_err("cached keys decide nothing while the issuer refuses");
    assert!(unavailable(&rejection));
    assert!(unavailable(&refreshing.await.unwrap().unwrap_err()));
}

#[tokio::test]
async fn retry_interval_is_thirty_seconds_or_a_shorter_ttl() {
    let server = MockServer::start().await;
    let cache = cache_with_mock_issuer(&server).await;
    assert_eq!(cache.ttl, Duration::from_hours(1));
    assert_eq!(cache.unanswered_retry_interval(), Duration::from_secs(30));

    let cache = JwksCache {
        ttl: Duration::from_secs(5),
        ..cache
    };
    assert_eq!(cache.unanswered_retry_interval(), Duration::from_secs(5));
}

#[tokio::test]
async fn issuer_is_asked_again_after_the_retry_interval() {
    let server = MockServer::start().await;
    let cache = aged(cache_with_mock_issuer(&server).await, TTL + MARGIN).await;
    let token = token(&server, TEST_KID);
    jwks_replies(&server, ResponseTemplate::new(503)).await;
    cache.validate_token(&token).await.unwrap();
    assert!(cache.last_unanswered_refresh.read().await.is_some());

    jwks_replies(&server, key_set(&[TEST_KID])).await;
    cache.validate_token(&token).await.unwrap();
    assert_eq!(
        hits(&server, JWKS).await,
        0,
        "the retry interval has not ended"
    );

    *cache.last_unanswered_refresh.write().await = Some(before_now(TTL + MARGIN));
    cache.validate_token(&token).await.unwrap();
    assert_eq!(hits(&server, JWKS).await, 1);
    assert!(cache.last_unanswered_refresh.read().await.is_none());
    assert!(cache.last_refresh.read().await.elapsed() < TTL);
}

#[tokio::test]
async fn requests_do_not_wait_for_a_refresh_another_request_started() {
    let server = MockServer::start().await;
    let cache = Arc::new(aged(cache_with_mock_issuer(&server).await, TTL + MARGIN).await);
    let token = token(&server, TEST_KID);
    jwks_replies(
        &server,
        key_set(&[TEST_KID]).set_delay(Duration::from_secs(3)),
    )
    .await;

    let refreshing = tokio::spawn({
        let (cache, token) = (cache.clone(), token.clone());
        async move { cache.validate_token(&token).await }
    });
    while hits(&server, JWKS).await == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    tokio::time::timeout(Duration::from_secs(1), cache.validate_token(&token))
        .await
        .expect("a request with recent keys does not wait for the refresh")
        .expect("recent keys decide while the refresh is in flight");
    refreshing.await.unwrap().unwrap();
}

#[tokio::test]
async fn no_keys_and_no_answer_refuses() {
    let server = MockServer::start().await;
    jwks_replies(&server, ResponseTemplate::new(503)).await;
    Mock::given(method("GET"))
        .and(path(DISCOVERY))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": server.uri(),
            "jwks_uri": format!("{}{JWKS}", server.uri()),
        })))
        .mount(&server)
        .await;

    JwksCache::new(&mock_issuer_config(&server))
        .await
        .expect_err("a cache cannot start without keys");
}

#[tokio::test]
async fn unknown_key_id_asks_the_issuer_once() {
    let server = MockServer::start().await;
    let cache = cache_with_mock_issuer(&server).await;
    jwks_replies(&server, key_set(&[TEST_KID, "rotated-in-key"])).await;
    let token = token(&server, "rotated-in-key");

    for _ in 0..5 {
        cache
            .validate_token(&token)
            .await
            .expect("a key the issuer rotated in is found by an early refresh");
    }

    assert_eq!(hits(&server, JWKS).await, 1);
}

#[tokio::test]
async fn unknown_key_id_without_an_answer_stays_undecided_through_the_cooldown() {
    let server = MockServer::start().await;
    let cache = cache_with_mock_issuer(&server).await;
    jwks_replies(&server, ResponseTemplate::new(503)).await;
    let token = token(&server, "rotated-in-key");

    let first = cache.validate_token(&token).await.unwrap_err();
    assert!(unavailable(&first));
    // Hold the next lookups inside the cooldown, however the test is scheduled.
    *cache.last_kid_miss_refresh.write().await =
        Instant::now().checked_add(Duration::from_mins(1)).unwrap();
    for _ in 0..3 {
        let throttled = cache.validate_token(&token).await.unwrap_err();
        assert!(
            unavailable(&throttled),
            "an unknown key is not a refusal while the issuer has not answered"
        );
    }
    assert_eq!(hits(&server, JWKS).await, 1);

    // Keys the cache holds still decide.
    cache
        .validate_token(&self::token(&server, TEST_KID))
        .await
        .expect("a cached key verifies while the issuer gives no answer");
}
