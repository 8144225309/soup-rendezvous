//! Event ingest pipeline.
//!
//! Takes a raw JSON byte slice posted by a client and produces an
//! [`IngestedEvent`] ready for the storage layer. The server parses
//! exactly enough of the envelope to extract index fields and treats
//! `scheme_payload`, `signature`, `nonce`, and every other field as
//! opaque. No signature verification, no canonicalization, no schema
//! validation beyond the envelope shape.

use serde_json::{Map, Value};

use crate::db::{EventId, EventKind, IngestedEvent, Pubkey};

/// Errors returned when an envelope cannot be parsed for indexing.
/// All variants carry a static-string reason — no PII, safe to leak
/// in HTTP error responses.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("body is not valid json")]
    InvalidJson,
    #[error("body must be a json object")]
    NotAnObject,
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("field {field} has wrong type, expected {expected}")]
    WrongType {
        field: &'static str,
        expected: &'static str,
    },
    #[error("unknown event type")]
    UnknownType,
    #[error("field {field} has invalid hex (expected 32-byte hex string)")]
    InvalidHex { field: &'static str },
    #[error("field {field} has invalid timestamp (expected RFC 3339)")]
    InvalidTimestamp { field: &'static str },
    #[error("field scheme must be non-empty")]
    EmptyScheme,
}

/// Parse the envelope of a posted event and produce an [`IngestedEvent`]
/// ready to hand to the storage layer.
///
/// The body is stored verbatim in the returned event — the server serves
/// it back unmodified on subsequent fetches.
pub fn extract_metadata(body: &[u8]) -> Result<IngestedEvent, IngestError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| IngestError::InvalidJson)?;
    let obj = value.as_object().ok_or(IngestError::NotAnObject)?;

    let type_str = get_str(obj, "type")?;
    let kind = EventKind::parse_type(type_str).ok_or(IngestError::UnknownType)?;

    let scheme = get_str(obj, "scheme")?.to_string();
    if scheme.is_empty() {
        return Err(IngestError::EmptyScheme);
    }

    let created_at = parse_timestamp(get_str(obj, "created_at")?, "created_at")?;
    let tags = get_tags(obj)?;

    let (host_pubkey, joiner_pubkey, cohort_field, expires_at) = match kind {
        EventKind::Advertisement => {
            let host = get_pubkey(obj, "host_pubkey")?;
            (Some(host), None, None, None)
        }
        EventKind::JoinAttestation => {
            let joiner = get_pubkey(obj, "joiner_pubkey")?;
            let cohort = get_event_id(obj, "advertisement_id")?;
            let expires = parse_timestamp(get_str(obj, "expires_at")?, "expires_at")?;
            (None, Some(joiner), Some(cohort), Some(expires))
        }
        EventKind::SealedCohort => {
            let host = get_pubkey(obj, "host_pubkey")?;
            let cohort = get_event_id(obj, "advertisement_id")?;
            (Some(host), None, Some(cohort), None)
        }
    };

    let id = EventId::from_body(body);

    // Advertisement events use their own id as the cohort_id, so a
    // single `WHERE cohort_id = ?` query returns the ad plus all of its
    // attestations and the seal in one shot.
    let cohort_id = if kind == EventKind::Advertisement {
        Some(id)
    } else {
        cohort_field
    };

    Ok(IngestedEvent {
        id,
        kind,
        scheme,
        host_pubkey,
        joiner_pubkey,
        cohort_id,
        created_at,
        expires_at,
        tags,
        body: body.to_vec(),
    })
}

fn get_str<'a>(obj: &'a Map<String, Value>, field: &'static str) -> Result<&'a str, IngestError> {
    let v = obj.get(field).ok_or(IngestError::MissingField(field))?;
    v.as_str().ok_or(IngestError::WrongType {
        field,
        expected: "string",
    })
}

fn get_pubkey(obj: &Map<String, Value>, field: &'static str) -> Result<Pubkey, IngestError> {
    let s = get_str(obj, field)?;
    Pubkey::from_hex(s).map_err(|_| IngestError::InvalidHex { field })
}

fn get_event_id(obj: &Map<String, Value>, field: &'static str) -> Result<EventId, IngestError> {
    let s = get_str(obj, field)?;
    EventId::from_hex(s).map_err(|_| IngestError::InvalidHex { field })
}

fn get_tags(obj: &Map<String, Value>) -> Result<Vec<String>, IngestError> {
    let Some(v) = obj.get("tags") else {
        return Ok(Vec::new());
    };
    let arr = v.as_array().ok_or(IngestError::WrongType {
        field: "tags",
        expected: "array of strings",
    })?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item.as_str().ok_or(IngestError::WrongType {
            field: "tags",
            expected: "array of strings",
        })?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn parse_timestamp(s: &str, field: &'static str) -> Result<i64, IngestError> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.timestamp())
        .map_err(|_| IngestError::InvalidTimestamp { field })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pk_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn id_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn body_of(v: &Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    #[test]
    fn parses_minimal_advertisement() {
        let v = json!({
            "protocol": "soup-rendezvous/0",
            "type": "advertisement",
            "scheme": "superscalar/v1",
            "host_pubkey": pk_hex(0xaa),
            "created_at": "2026-04-12T01:00:00Z",
            "scheme_payload": { "ignored": "by_server" },
            "signature": "deadbeef"
        });
        let body = body_of(&v);
        let ev = extract_metadata(&body).unwrap();

        assert_eq!(ev.kind, EventKind::Advertisement);
        assert_eq!(ev.scheme, "superscalar/v1");
        assert_eq!(ev.host_pubkey, Some(Pubkey([0xaa; 32])));
        assert_eq!(ev.joiner_pubkey, None);
        // Advertisements self-reference: cohort_id == id.
        assert_eq!(ev.cohort_id, Some(ev.id));
        assert_eq!(ev.expires_at, None);
        assert!(ev.tags.is_empty());
        // Body stored verbatim.
        assert_eq!(ev.body, body);
        // ID is sha256(body).
        assert_eq!(ev.id, EventId::from_body(&body));
    }

    #[test]
    fn parses_join_attestation_with_expires() {
        let ad_id = id_hex(0xa1);
        let v = json!({
            "protocol": "soup-rendezvous/0",
            "type": "join_attestation",
            "scheme": "superscalar/v1",
            "joiner_pubkey": pk_hex(0xbb),
            "advertisement_id": ad_id,
            "created_at": "2026-04-12T01:05:00Z",
            "expires_at": "2026-04-13T01:05:00Z",
            "scheme_payload": {},
            "nonce": "1234567890abcdef",
            "signature": "..."
        });
        let body = body_of(&v);
        let ev = extract_metadata(&body).unwrap();

        assert_eq!(ev.kind, EventKind::JoinAttestation);
        assert_eq!(ev.host_pubkey, None);
        assert_eq!(ev.joiner_pubkey, Some(Pubkey([0xbb; 32])));
        assert_eq!(ev.cohort_id, Some(EventId([0xa1; 32])));
        assert!(ev.expires_at.is_some());
        // Sanity: 24h apart
        assert_eq!(ev.expires_at.unwrap() - ev.created_at, 86400);
    }

    #[test]
    fn parses_sealed_cohort() {
        let ad_id = id_hex(0xa1);
        let v = json!({
            "protocol": "soup-rendezvous/0",
            "type": "sealed_cohort",
            "scheme": "superscalar/v1",
            "host_pubkey": pk_hex(0xaa),
            "advertisement_id": ad_id,
            "created_at": "2026-04-12T02:00:00Z",
            "members": [{"joiner_pubkey": pk_hex(1), "attestation_id": id_hex(2)}],
            "signature": "..."
        });
        let body = body_of(&v);
        let ev = extract_metadata(&body).unwrap();

        assert_eq!(ev.kind, EventKind::SealedCohort);
        assert_eq!(ev.host_pubkey, Some(Pubkey([0xaa; 32])));
        assert_eq!(ev.joiner_pubkey, None);
        assert_eq!(ev.cohort_id, Some(EventId([0xa1; 32])));
        assert_eq!(ev.expires_at, None);
    }

    #[test]
    fn extracts_tags() {
        let v = json!({
            "type": "advertisement",
            "scheme": "superscalar/v1",
            "host_pubkey": pk_hex(1),
            "created_at": "2026-04-12T01:00:00Z",
            "tags": ["en", "europe", "evening"]
        });
        let ev = extract_metadata(&body_of(&v)).unwrap();
        assert_eq!(ev.tags, vec!["en", "europe", "evening"]);
    }

    #[test]
    fn id_is_stable_across_reparses() {
        let v = json!({
            "type": "advertisement",
            "scheme": "superscalar/v1",
            "host_pubkey": pk_hex(1),
            "created_at": "2026-04-12T01:00:00Z"
        });
        let body = body_of(&v);
        let a = extract_metadata(&body).unwrap();
        let b = extract_metadata(&body).unwrap();
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn body_stored_verbatim_with_unknown_fields() {
        let v = json!({
            "type": "advertisement",
            "scheme": "superscalar/v1",
            "host_pubkey": pk_hex(1),
            "created_at": "2026-04-12T01:00:00Z",
            "scheme_payload": {
                "lsp_pubkey": "02deadbeef",
                "total_funding_sat": "10000000",
                "any_future_field": [1, 2, 3]
            },
            "name": "alpha-leaf-utc-evening",
            "description": "anything",
            "min_members": 4,
            "approval_mode": "manual",
            "nonce": "f4e9c1",
            "signature": "deadbeef"
        });
        let body = body_of(&v);
        let ev = extract_metadata(&body).unwrap();
        assert_eq!(ev.body, body);
    }

    #[test]
    fn rejects_invalid_json() {
        let err = extract_metadata(b"not json").unwrap_err();
        assert!(matches!(err, IngestError::InvalidJson));
    }

    #[test]
    fn rejects_non_object() {
        let err = extract_metadata(b"[1, 2, 3]").unwrap_err();
        assert!(matches!(err, IngestError::NotAnObject));
        let err = extract_metadata(b"\"string\"").unwrap_err();
        assert!(matches!(err, IngestError::NotAnObject));
        let err = extract_metadata(b"42").unwrap_err();
        assert!(matches!(err, IngestError::NotAnObject));
    }

    #[test]
    fn rejects_missing_type() {
        let v =
            json!({"scheme": "x", "host_pubkey": pk_hex(1), "created_at": "2026-04-12T01:00:00Z"});
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(err, IngestError::MissingField("type")));
    }

    #[test]
    fn rejects_unknown_type() {
        let v = json!({
            "type": "drumroll_please",
            "scheme": "x",
            "host_pubkey": pk_hex(1),
            "created_at": "2026-04-12T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(err, IngestError::UnknownType));
    }

    #[test]
    fn rejects_missing_scheme() {
        let v = json!({
            "type": "advertisement",
            "host_pubkey": pk_hex(1),
            "created_at": "2026-04-12T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(err, IngestError::MissingField("scheme")));
    }

    #[test]
    fn rejects_empty_scheme() {
        let v = json!({
            "type": "advertisement",
            "scheme": "",
            "host_pubkey": pk_hex(1),
            "created_at": "2026-04-12T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(err, IngestError::EmptyScheme));
    }

    #[test]
    fn rejects_missing_created_at() {
        let v = json!({
            "type": "advertisement",
            "scheme": "x",
            "host_pubkey": pk_hex(1)
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(err, IngestError::MissingField("created_at")));
    }

    #[test]
    fn rejects_invalid_timestamp() {
        let v = json!({
            "type": "advertisement",
            "scheme": "x",
            "host_pubkey": pk_hex(1),
            "created_at": "yesterday at noon"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(
            err,
            IngestError::InvalidTimestamp {
                field: "created_at"
            }
        ));
    }

    #[test]
    fn rejects_advertisement_missing_host_pubkey() {
        let v = json!({
            "type": "advertisement",
            "scheme": "x",
            "created_at": "2026-04-12T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(err, IngestError::MissingField("host_pubkey")));
    }

    #[test]
    fn rejects_invalid_hex_pubkey() {
        let v = json!({
            "type": "advertisement",
            "scheme": "x",
            "host_pubkey": "not-hex",
            "created_at": "2026-04-12T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(
            err,
            IngestError::InvalidHex {
                field: "host_pubkey"
            }
        ));
    }

    #[test]
    fn rejects_short_hex_pubkey() {
        let v = json!({
            "type": "advertisement",
            "scheme": "x",
            "host_pubkey": "deadbeef",
            "created_at": "2026-04-12T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(
            err,
            IngestError::InvalidHex {
                field: "host_pubkey"
            }
        ));
    }

    #[test]
    fn rejects_join_attestation_missing_joiner_pubkey() {
        let v = json!({
            "type": "join_attestation",
            "scheme": "x",
            "advertisement_id": id_hex(1),
            "created_at": "2026-04-12T01:00:00Z",
            "expires_at": "2026-04-13T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(err, IngestError::MissingField("joiner_pubkey")));
    }

    #[test]
    fn rejects_join_attestation_missing_advertisement_id() {
        let v = json!({
            "type": "join_attestation",
            "scheme": "x",
            "joiner_pubkey": pk_hex(2),
            "created_at": "2026-04-12T01:00:00Z",
            "expires_at": "2026-04-13T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(err, IngestError::MissingField("advertisement_id")));
    }

    #[test]
    fn rejects_join_attestation_missing_expires_at() {
        let v = json!({
            "type": "join_attestation",
            "scheme": "x",
            "joiner_pubkey": pk_hex(2),
            "advertisement_id": id_hex(1),
            "created_at": "2026-04-12T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(err, IngestError::MissingField("expires_at")));
    }

    #[test]
    fn rejects_sealed_cohort_missing_advertisement_id() {
        let v = json!({
            "type": "sealed_cohort",
            "scheme": "x",
            "host_pubkey": pk_hex(1),
            "created_at": "2026-04-12T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(err, IngestError::MissingField("advertisement_id")));
    }

    #[test]
    fn rejects_wrong_type_field() {
        let v = json!({
            "type": "advertisement",
            "scheme": 12345,
            "host_pubkey": pk_hex(1),
            "created_at": "2026-04-12T01:00:00Z"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(
            err,
            IngestError::WrongType {
                field: "scheme",
                expected: "string"
            }
        ));
    }

    #[test]
    fn rejects_tags_not_array() {
        let v = json!({
            "type": "advertisement",
            "scheme": "x",
            "host_pubkey": pk_hex(1),
            "created_at": "2026-04-12T01:00:00Z",
            "tags": "europe"
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(
            err,
            IngestError::WrongType {
                field: "tags",
                expected: "array of strings"
            }
        ));
    }

    #[test]
    fn rejects_tags_with_non_string_element() {
        let v = json!({
            "type": "advertisement",
            "scheme": "x",
            "host_pubkey": pk_hex(1),
            "created_at": "2026-04-12T01:00:00Z",
            "tags": ["en", 42]
        });
        let err = extract_metadata(&body_of(&v)).unwrap_err();
        assert!(matches!(
            err,
            IngestError::WrongType {
                field: "tags",
                expected: "array of strings"
            }
        ));
    }
}
