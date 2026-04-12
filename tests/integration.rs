//! Integration tests. Spawn the full HTTP server in-process against an
//! in-memory database, hit it with reqwest, and assert end-to-end
//! behavior.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::{Value, json};
use soup_rendezvous::db::Db;
use soup_rendezvous::db::sqlite::SqliteDb;
use soup_rendezvous::http::{AppState, HttpLimits, build_router};

async fn spawn_app() -> SocketAddr {
    spawn_app_with_limits(HttpLimits::permissive_for_tests()).await
}

async fn spawn_app_with_limits(limits: HttpLimits) -> SocketAddr {
    let db: Arc<dyn Db> = Arc::new(SqliteDb::open_in_memory().unwrap());
    let state = AppState {
        db,
        limits: Arc::new(limits),
    };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn iso_offset(offset_secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(offset_secs)).to_rfc3339()
}

fn pk_hex(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn id_hex(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn ad_body(host_byte: u8) -> Value {
    json!({
        "protocol": "soup-rendezvous/0",
        "type": "advertisement",
        "scheme": "superscalar/v1",
        "host_pubkey": pk_hex(host_byte),
        "name": "test cohort",
        "min_members": 4,
        "max_members": 8,
        "approval_mode": "manual",
        "join_window_opens_at": now_iso(),
        "join_window_closes_at": iso_offset(7 * 86400),
        "created_at": now_iso(),
        "nonce": "f4e9c1aabbccddee",
        "scheme_payload": {
            "lsp_pubkey": "02deadbeef",
            "total_funding_sat": "10000000"
        },
        "signature": "deadbeef"
    })
}

fn attestation_body(joiner_byte: u8, advertisement_id: &str) -> Value {
    json!({
        "protocol": "soup-rendezvous/0",
        "type": "join_attestation",
        "scheme": "superscalar/v1",
        "joiner_pubkey": pk_hex(joiner_byte),
        "advertisement_id": advertisement_id,
        "created_at": now_iso(),
        "expires_at": iso_offset(86400),
        "nonce": "0123456789abcdef",
        "signature": "..."
    })
}

fn seal_body(host_byte: u8, advertisement_id: &str) -> Value {
    json!({
        "protocol": "soup-rendezvous/0",
        "type": "sealed_cohort",
        "scheme": "superscalar/v1",
        "host_pubkey": pk_hex(host_byte),
        "advertisement_id": advertisement_id,
        "members": [
            {"joiner_pubkey": pk_hex(0xb1), "attestation_id": id_hex(0xc1)}
        ],
        "created_at": now_iso(),
        "signature": "..."
    })
}

async fn post_event(client: &reqwest::Client, addr: SocketAddr, body: &Value) -> reqwest::Response {
    client
        .post(format!("http://{addr}/v0/events"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(body).unwrap())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn health_endpoint() {
    let addr = spawn_app().await;
    let res = reqwest::get(format!("http://{addr}/v0/health"))
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn post_then_get_round_trip() {
    let addr = spawn_app().await;
    let client = reqwest::Client::new();
    let body = ad_body(0xaa);

    let resp = post_event(&client, addr, &body).await;
    assert_eq!(resp.status(), 201);
    let posted: Value = resp.json().await.unwrap();
    let id = posted["id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 64); // 32-byte hex

    let resp = client
        .get(format!("http://{addr}/v0/events/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .map(|h| h.to_str().unwrap()),
        Some("application/json")
    );
    let fetched: Value = resp.json().await.unwrap();
    // Server returns the body verbatim — every field we posted should be there.
    assert_eq!(fetched["type"], "advertisement");
    assert_eq!(fetched["scheme"], "superscalar/v1");
    assert_eq!(fetched["host_pubkey"], pk_hex(0xaa));
    assert_eq!(fetched["scheme_payload"]["total_funding_sat"], "10000000");
}

#[tokio::test]
async fn idempotent_post() {
    let addr = spawn_app().await;
    let client = reqwest::Client::new();
    let body = ad_body(0xbb);

    let r1 = post_event(&client, addr, &body)
        .await
        .json::<Value>()
        .await
        .unwrap();
    let r2 = post_event(&client, addr, &body)
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(r1["id"], r2["id"]);

    // The list should contain exactly one event.
    let listed: Value = reqwest::get(format!("http://{addr}/v0/events"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed["events"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn get_unknown_id_is_404() {
    let addr = spawn_app().await;
    let unknown = "0".repeat(64);
    let res = reqwest::get(format!("http://{addr}/v0/events/{unknown}"))
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "not found");
}

#[tokio::test]
async fn get_invalid_hex_is_404() {
    let addr = spawn_app().await;
    let res = reqwest::get(format!("http://{addr}/v0/events/not-valid-hex"))
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn post_malformed_json_is_400() {
    let addr = spawn_app().await;
    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{addr}/v0/events"))
        .header("content-type", "application/json")
        .body("not json".to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn post_missing_field_is_400() {
    let addr = spawn_app().await;
    let client = reqwest::Client::new();
    let body = json!({
        "type": "advertisement",
        "scheme": "superscalar/v1"
        // missing host_pubkey, created_at
    });
    let res = post_event(&client, addr, &body).await;
    assert_eq!(res.status(), 400);
    let err: Value = res.json().await.unwrap();
    assert!(err["error"].as_str().unwrap().contains("created_at"));
}

#[tokio::test]
async fn list_filters_by_kind() {
    let addr = spawn_app().await;
    let client = reqwest::Client::new();

    let ad = ad_body(0xaa);
    let post = post_event(&client, addr, &ad)
        .await
        .json::<Value>()
        .await
        .unwrap();
    let ad_id = post["id"].as_str().unwrap().to_string();

    let att = attestation_body(0x11, &ad_id);
    post_event(&client, addr, &att).await;

    let list_all: Value = reqwest::get(format!("http://{addr}/v0/events"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list_all["events"].as_array().unwrap().len(), 2);

    let list_ads: Value = reqwest::get(format!("http://{addr}/v0/events?kind=advertisement"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list_ads["events"].as_array().unwrap().len(), 1);
    assert_eq!(list_ads["events"][0]["kind"], "advertisement");

    let list_atts: Value = reqwest::get(format!("http://{addr}/v0/events?kind=join_attestation"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list_atts["events"].as_array().unwrap().len(), 1);
    assert_eq!(list_atts["events"][0]["kind"], "join_attestation");
}

#[tokio::test]
async fn list_rejects_bad_kind() {
    let addr = spawn_app().await;
    let res = reqwest::get(format!("http://{addr}/v0/events?kind=bogus"))
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn cohort_endpoint_returns_ad_attestations_and_seal() {
    let addr = spawn_app().await;
    let client = reqwest::Client::new();

    let ad = ad_body(0xaa);
    let ad_id = post_event(&client, addr, &ad)
        .await
        .json::<Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    for joiner in [0x11u8, 0x22, 0x33] {
        post_event(&client, addr, &attestation_body(joiner, &ad_id)).await;
    }

    post_event(&client, addr, &seal_body(0xaa, &ad_id)).await;

    let cohort: Value = reqwest::get(format!("http://{addr}/v0/cohorts/{ad_id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(cohort["advertisement"]["id"], ad_id);
    assert_eq!(cohort["advertisement"]["kind"], "advertisement");
    assert_eq!(cohort["attestations"].as_array().unwrap().len(), 3);
    assert!(cohort["seal"].is_object());
    assert_eq!(cohort["seal"]["kind"], "sealed_cohort");

    // Envelope is the parsed body, not a string.
    assert_eq!(
        cohort["advertisement"]["envelope"]["scheme_payload"]["total_funding_sat"],
        "10000000"
    );
}

#[tokio::test]
async fn cohort_endpoint_unsealed_returns_null_seal() {
    let addr = spawn_app().await;
    let client = reqwest::Client::new();

    let ad = ad_body(0xaa);
    let ad_id = post_event(&client, addr, &ad)
        .await
        .json::<Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    post_event(&client, addr, &attestation_body(0x11, &ad_id)).await;

    let cohort: Value = reqwest::get(format!("http://{addr}/v0/cohorts/{ad_id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cohort["attestations"].as_array().unwrap().len(), 1);
    assert!(cohort["seal"].is_null());
}

#[tokio::test]
async fn cohort_endpoint_unknown_is_404() {
    let addr = spawn_app().await;
    let unknown = "0".repeat(64);
    let res = reqwest::get(format!("http://{addr}/v0/cohorts/{unknown}"))
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

// ---------------------------------------------------------------------
// Phase 4: rate limiting + abuse protection
// ---------------------------------------------------------------------

#[tokio::test]
async fn body_too_large_is_413() {
    // 1 KB body cap; the ad body with a giant `description` field will
    // sail past it.
    let limits = HttpLimits {
        max_body_bytes: 1024,
        ..HttpLimits::permissive_for_tests()
    };
    let addr = spawn_app_with_limits(limits).await;
    let client = reqwest::Client::new();

    let mut body = ad_body(0xaa);
    body["description"] = Value::String("x".repeat(8 * 1024));

    let res = post_event(&client, addr, &body).await;
    assert_eq!(res.status(), 413);
}

#[tokio::test]
async fn stale_created_at_is_rejected() {
    let limits = HttpLimits {
        clock_skew_secs: 60,
        ..HttpLimits::permissive_for_tests()
    };
    let addr = spawn_app_with_limits(limits).await;
    let client = reqwest::Client::new();

    let mut body = ad_body(0xaa);
    // Two hours in the past — well outside ±60s.
    body["created_at"] = Value::String(iso_offset(-7200));

    let res = post_event(&client, addr, &body).await;
    assert_eq!(res.status(), 400);
    let err: Value = res.json().await.unwrap();
    assert!(err["error"].as_str().unwrap().contains("clock skew"));
}

#[tokio::test]
async fn future_created_at_is_rejected() {
    let limits = HttpLimits {
        clock_skew_secs: 60,
        ..HttpLimits::permissive_for_tests()
    };
    let addr = spawn_app_with_limits(limits).await;
    let client = reqwest::Client::new();

    let mut body = ad_body(0xaa);
    body["created_at"] = Value::String(iso_offset(7200));

    let res = post_event(&client, addr, &body).await;
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn pubkey_storage_quota_returns_429() {
    // Each ad body lands around 1.5 KB after timestamps and the
    // 900-char description. With a 4 KB quota, two posts fit comfortably
    // and the third pushes the running total past the cap.
    let limits = HttpLimits {
        pubkey_quota_bytes: 4096,
        ..HttpLimits::permissive_for_tests()
    };
    let addr = spawn_app_with_limits(limits).await;
    let client = reqwest::Client::new();

    let mut a1 = ad_body(0xaa);
    a1["description"] = Value::String("x".repeat(900));
    a1["nonce"] = Value::String("first".into());
    let r1 = post_event(&client, addr, &a1).await;
    assert_eq!(r1.status(), 201);

    let mut a2 = ad_body(0xaa);
    a2["description"] = Value::String("y".repeat(900));
    a2["nonce"] = Value::String("second".into());
    let r2 = post_event(&client, addr, &a2).await;
    assert_eq!(r2.status(), 201);

    let mut a3 = ad_body(0xaa);
    a3["description"] = Value::String("z".repeat(900));
    a3["nonce"] = Value::String("third".into());
    let r3 = post_event(&client, addr, &a3).await;
    assert_eq!(r3.status(), 429);
    let err: Value = r3.json().await.unwrap();
    assert!(err["error"].as_str().unwrap().contains("quota"));
}

#[tokio::test]
async fn rate_limit_kicks_in_under_burst() {
    let limits = HttpLimits {
        rate_per_sec: 1,
        rate_burst: 3,
        ..HttpLimits::permissive_for_tests()
    };
    let addr = spawn_app_with_limits(limits).await;
    let client = reqwest::Client::new();

    let mut last_status = 0;
    let mut hit_429 = false;
    for _ in 0..20u8 {
        let res = client
            .get(format!("http://{addr}/v0/events?kind=advertisement"))
            .send()
            .await
            .unwrap();
        last_status = res.status().as_u16();
        if last_status == 429 {
            hit_429 = true;
            break;
        }
    }
    assert!(
        hit_429,
        "expected at least one 429 within 20 burst requests, last status was {last_status}"
    );
}

#[tokio::test]
async fn health_endpoint_is_not_rate_limited() {
    let limits = HttpLimits {
        rate_per_sec: 1,
        rate_burst: 1,
        ..HttpLimits::permissive_for_tests()
    };
    let addr = spawn_app_with_limits(limits).await;
    let client = reqwest::Client::new();

    // Hammer health 10 times — none should be rejected because health
    // is on the unlimited router branch.
    for _ in 0..10u8 {
        let res = client
            .get(format!("http://{addr}/v0/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
    }
}
