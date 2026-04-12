//! HTTP layer.
//!
//! - `POST /v0/events`               publish (idempotent by content hash)
//! - `GET  /v0/events/{id}`          fetch raw envelope by content hash
//! - `GET  /v0/events?...`           list with filters (metadata only)
//! - `GET  /v0/cohorts/{id}`         hydrated ad + attestations + seal
//! - `GET  /v0/health`               liveness
//!
//! All POSTs accept any opaque JSON body up to a body-size cap enforced
//! by the `DefaultBodyLimit` layer. The server computes
//! `sha256(body)` -> id, extracts indexable metadata via
//! [`crate::event::extract_metadata`], and stores. The server never
//! verifies signatures, never canonicalizes, and never parses the
//! `scheme_payload`.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower::ServiceBuilder;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::db::{Db, EventFilter, EventId, EventKind, Pubkey, StoredEvent};
use crate::error::ApiError;
use crate::event::extract_metadata;

/// Configurable limits applied at the HTTP boundary. Held by [`AppState`]
/// so handlers can inspect them and so [`build_router`] can install the
/// appropriate tower layers.
#[derive(Debug, Clone)]
pub struct HttpLimits {
    pub max_body_bytes: usize,
    pub rate_per_sec: u32,
    pub rate_burst: u32,
    pub pubkey_quota_bytes: u64,
    pub clock_skew_secs: i64,
    pub timeout_secs: u64,
}

impl HttpLimits {
    /// Generous defaults suitable for tests where no defense should
    /// trip incidentally. Real deployments use [`Default`] or pass
    /// values from the CLI config.
    pub fn permissive_for_tests() -> Self {
        Self {
            max_body_bytes: 1_048_576,
            rate_per_sec: 1_000,
            rate_burst: 10_000,
            pubkey_quota_bytes: 1_073_741_824,
            clock_skew_secs: 86_400,
            timeout_secs: 60,
        }
    }
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 65_536,
            rate_per_sec: 5,
            rate_burst: 30,
            pubkey_quota_bytes: 1_048_576,
            clock_skew_secs: 300,
            timeout_secs: 30,
        }
    }
}

/// Shared application state held in axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn Db>,
    pub limits: Arc<HttpLimits>,
}

/// Build the router for the application. Installs the configured tower
/// layers (rate limit, body size cap, timeout, trace) on every route
/// except `/v0/health`, which is excluded from the rate limit so liveness
/// probes can't be locked out by another client's burst.
pub fn build_router(state: AppState) -> Router {
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(state.limits.rate_per_sec.max(1) as u64)
            .burst_size(state.limits.rate_burst.max(1))
            .finish()
            .expect("valid governor config"),
    );

    let limited = Router::new()
        .route("/v0/events", post(post_event).get(list_events))
        .route("/v0/events/{id}", get(get_event))
        .route("/v0/cohorts/{id}", get(get_cohort))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    Duration::from_secs(state.limits.timeout_secs),
                ))
                .layer(GovernorLayer {
                    config: governor_conf,
                })
                .layer(DefaultBodyLimit::max(state.limits.max_body_bytes)),
        );

    Router::new()
        .route("/v0/health", get(health))
        .merge(limited)
        .with_state(state)
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------

async fn health() -> &'static str {
    "ok"
}

async fn post_event(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let ingested = extract_metadata(&body)?;

    // Reject events whose declared created_at is too far from the
    // server clock. Catches stale events being replayed and clients
    // with badly-skewed clocks.
    let now = chrono::Utc::now().timestamp();
    let skew = (ingested.created_at - now).abs();
    if skew > state.limits.clock_skew_secs {
        return Err(ApiError::BadRequest(
            "created_at outside allowed clock skew window",
        ));
    }

    // Per-pubkey storage quota. The author pubkey for an advertisement
    // or seal is the host; for an attestation it's the joiner. The
    // check is best-effort and racy under concurrent posts from the
    // same key, which is acceptable for the prototype: the worst case
    // is the quota overshoots by one body's size between concurrent
    // requests.
    if let Some(author) = ingested.author_pubkey() {
        let used = state.db.bytes_stored_by_pubkey(&author)?;
        let new_total = used.saturating_add(ingested.body.len() as u64);
        if new_total > state.limits.pubkey_quota_bytes {
            return Err(ApiError::QuotaExceeded("pubkey storage quota exceeded"));
        }
    }

    let id = state.db.put_event(&ingested)?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id.to_hex() }))))
}

async fn get_event(
    State(state): State<AppState>,
    Path(id_hex): Path<String>,
) -> Result<Response, ApiError> {
    let id = EventId::from_hex(&id_hex).map_err(|_| ApiError::NotFound)?;
    let ev = state.db.get_by_id(&id)?.ok_or(ApiError::NotFound)?;
    Ok(raw_json_response(ev.body))
}

async fn list_events(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse>, ApiError> {
    let filter = query.into_filter()?;
    let events = state.db.list(&filter)?;
    Ok(Json(ListResponse {
        events: events.into_iter().map(EventListItem::from).collect(),
    }))
}

async fn get_cohort(
    State(state): State<AppState>,
    Path(id_hex): Path<String>,
) -> Result<Json<CohortResponse>, ApiError> {
    let cohort_id = EventId::from_hex(&id_hex).map_err(|_| ApiError::NotFound)?;
    let events = state.db.list(&EventFilter {
        cohort_id: Some(cohort_id),
        include_expired: true,
        limit: Some(1000),
        ..EventFilter::default()
    })?;

    let mut advertisement: Option<EventDetail> = None;
    let mut attestations: Vec<EventDetail> = Vec::new();
    let mut seal: Option<EventDetail> = None;

    for ev in events {
        match ev.kind {
            EventKind::Advertisement => advertisement = Some(EventDetail::try_from(ev)?),
            EventKind::JoinAttestation => attestations.push(EventDetail::try_from(ev)?),
            EventKind::SealedCohort => seal = Some(EventDetail::try_from(ev)?),
        }
    }

    if advertisement.is_none() && attestations.is_empty() && seal.is_none() {
        return Err(ApiError::NotFound);
    }

    Ok(Json(CohortResponse {
        advertisement,
        attestations,
        seal,
    }))
}

// ---------------------------------------------------------------------
// Query / response DTOs
// ---------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    kind: Option<String>,
    scheme: Option<String>,
    cohort: Option<String>,
    host: Option<String>,
    since: Option<i64>,
    limit: Option<u32>,
    offset: Option<u32>,
    include_expired: Option<bool>,
}

impl ListQuery {
    fn into_filter(self) -> Result<EventFilter, ApiError> {
        let kind = match self.kind.as_deref() {
            None => None,
            Some(s) => Some(EventKind::parse_type(s).ok_or(ApiError::BadRequest(
                "kind must be one of advertisement, join_attestation, sealed_cohort",
            ))?),
        };
        let cohort_id = match self.cohort.as_deref() {
            None => None,
            Some(s) => Some(
                EventId::from_hex(s)
                    .map_err(|_| ApiError::BadRequest("cohort must be 32-byte hex"))?,
            ),
        };
        let host_pubkey = match self.host.as_deref() {
            None => None,
            Some(s) => Some(
                Pubkey::from_hex(s)
                    .map_err(|_| ApiError::BadRequest("host must be 32-byte hex"))?,
            ),
        };
        Ok(EventFilter {
            kind,
            scheme: self.scheme,
            cohort_id,
            host_pubkey,
            since: self.since,
            limit: self.limit,
            offset: self.offset,
            include_expired: self.include_expired.unwrap_or(false),
        })
    }
}

#[derive(Debug, Serialize)]
struct ListResponse {
    events: Vec<EventListItem>,
}

#[derive(Debug, Serialize)]
struct EventListItem {
    id: String,
    kind: &'static str,
    scheme: String,
    host_pubkey: Option<String>,
    joiner_pubkey: Option<String>,
    cohort_id: Option<String>,
    created_at: i64,
    expires_at: Option<i64>,
}

impl From<StoredEvent> for EventListItem {
    fn from(e: StoredEvent) -> Self {
        Self {
            id: e.id.to_hex(),
            kind: e.kind.type_str(),
            scheme: e.scheme,
            host_pubkey: e.host_pubkey.map(|p| p.to_hex()),
            joiner_pubkey: e.joiner_pubkey.map(|p| p.to_hex()),
            cohort_id: e.cohort_id.map(|c| c.to_hex()),
            created_at: e.created_at,
            expires_at: e.expires_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct EventDetail {
    id: String,
    kind: &'static str,
    scheme: String,
    host_pubkey: Option<String>,
    joiner_pubkey: Option<String>,
    cohort_id: Option<String>,
    created_at: i64,
    expires_at: Option<i64>,
    envelope: Value,
}

impl TryFrom<StoredEvent> for EventDetail {
    type Error = ApiError;

    fn try_from(e: StoredEvent) -> Result<Self, Self::Error> {
        let envelope: Value = serde_json::from_slice(&e.body)
            .map_err(|err| ApiError::Internal(anyhow::Error::new(err)))?;
        Ok(Self {
            id: e.id.to_hex(),
            kind: e.kind.type_str(),
            scheme: e.scheme,
            host_pubkey: e.host_pubkey.map(|p| p.to_hex()),
            joiner_pubkey: e.joiner_pubkey.map(|p| p.to_hex()),
            cohort_id: e.cohort_id.map(|c| c.to_hex()),
            created_at: e.created_at,
            expires_at: e.expires_at,
            envelope,
        })
    }
}

#[derive(Debug, Serialize)]
struct CohortResponse {
    advertisement: Option<EventDetail>,
    attestations: Vec<EventDetail>,
    seal: Option<EventDetail>,
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Return a stored body verbatim with `content-type: application/json`.
/// We don't reparse here — the bytes are exactly what the client posted.
fn raw_json_response(body: Vec<u8>) -> Response {
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_ok() {
        assert_eq!(health().await, "ok");
    }

    #[test]
    fn http_limits_defaults_are_sensible() {
        let l = HttpLimits::default();
        assert!(l.max_body_bytes >= 16_384);
        assert!(l.rate_per_sec >= 1);
        assert!(l.clock_skew_secs >= 60);
    }
}
