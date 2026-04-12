use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::db::DbError;
use crate::event::IngestError;

/// Errors returned across the HTTP boundary. Each variant maps to a
/// specific status code and a JSON `{"error": "..."}` body. Variants
/// only carry static-string reasons or already-validated data; nothing
/// in here should ever leak server-internal detail to clients.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(#[from] IngestError),

    #[error("invalid request: {0}")]
    BadRequest(&'static str),

    #[error("quota exceeded: {0}")]
    QuotaExceeded(&'static str),

    #[error("internal error")]
    Internal(#[source] anyhow::Error),
}

impl From<DbError> for ApiError {
    fn from(e: DbError) -> Self {
        Self::Internal(anyhow::Error::new(e))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            Self::InvalidEnvelope(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, (*msg).to_string()),
            Self::QuotaExceeded(msg) => (StatusCode::TOO_MANY_REQUESTS, (*msg).to_string()),
            Self::Internal(e) => {
                tracing::error!(error = ?e, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
