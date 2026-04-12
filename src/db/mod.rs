pub mod sqlite;

use sha2::{Digest, Sha256};

/// 32-byte content-addressed event ID = sha256(event body bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventId(pub [u8; 32]);

impl EventId {
    pub fn from_body(body: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(body);
        let out = h.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&out);
        Self(id)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, ParseError> {
        let v = hex::decode(s).map_err(|_| ParseError::InvalidHex)?;
        if v.len() != 32 {
            return Err(ParseError::WrongLength {
                expected: 32,
                got: v.len(),
            });
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        Ok(Self(a))
    }
}

/// 32-byte BIP-340 x-only pubkey. The server treats it as opaque bytes
/// — no signature verification, no curve operations, just an identifier
/// for rate-limit bucketing and indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, ParseError> {
        let v = hex::decode(s).map_err(|_| ParseError::InvalidHex)?;
        if v.len() != 32 {
            return Err(ParseError::WrongLength {
                expected: 32,
                got: v.len(),
            });
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        Ok(Self(a))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid hex")]
    InvalidHex,
    #[error("wrong byte length: expected {expected}, got {got}")]
    WrongLength { expected: usize, got: usize },
}

/// The three event kinds, integer-coded for storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum EventKind {
    Advertisement = 1,
    JoinAttestation = 2,
    SealedCohort = 3,
}

impl EventKind {
    pub fn parse_type(s: &str) -> Option<Self> {
        match s {
            "advertisement" => Some(Self::Advertisement),
            "join_attestation" => Some(Self::JoinAttestation),
            "sealed_cohort" => Some(Self::SealedCohort),
            _ => None,
        }
    }

    pub fn type_str(&self) -> &'static str {
        match self {
            Self::Advertisement => "advertisement",
            Self::JoinAttestation => "join_attestation",
            Self::SealedCohort => "sealed_cohort",
        }
    }

    pub fn as_int(&self) -> i64 {
        *self as i64
    }

    pub fn from_int(i: i64) -> Option<Self> {
        match i {
            1 => Some(Self::Advertisement),
            2 => Some(Self::JoinAttestation),
            3 => Some(Self::SealedCohort),
            _ => None,
        }
    }
}

/// An event ready to be stored. The body is the raw bytes the client posted;
/// the server treats it as opaque. The other fields are extracted from the
/// envelope by `extract_metadata` (Phase 2) or constructed by tests.
#[derive(Debug, Clone)]
pub struct IngestedEvent {
    pub id: EventId,
    pub kind: EventKind,
    pub scheme: String,
    pub host_pubkey: Option<Pubkey>,
    pub joiner_pubkey: Option<Pubkey>,
    pub cohort_id: Option<EventId>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub tags: Vec<String>,
    pub body: Vec<u8>,
}

impl IngestedEvent {
    /// The pubkey that authored this event. For an advertisement or
    /// sealed_cohort that's the host_pubkey; for a join_attestation
    /// that's the joiner_pubkey. Returns None only if the event was
    /// constructed without either, which never happens via the
    /// extract_metadata pipeline.
    pub fn author_pubkey(&self) -> Option<Pubkey> {
        self.host_pubkey.or(self.joiner_pubkey)
    }
}

/// An event read back from storage.
#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub id: EventId,
    pub kind: EventKind,
    pub scheme: String,
    pub host_pubkey: Option<Pubkey>,
    pub joiner_pubkey: Option<Pubkey>,
    pub cohort_id: Option<EventId>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub body: Vec<u8>,
}

/// Filter for the list endpoint. All fields are AND-combined; None means
/// no constraint on that axis.
#[derive(Debug, Default, Clone)]
pub struct EventFilter {
    pub kind: Option<EventKind>,
    pub scheme: Option<String>,
    pub cohort_id: Option<EventId>,
    pub host_pubkey: Option<Pubkey>,
    pub since: Option<i64>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub include_expired: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("connection pool: {0}")]
    Pool(#[from] r2d2::Error),
    #[error("invalid stored event: {0}")]
    InvalidStored(&'static str),
}

/// Storage backend. Send + Sync + 'static so we can stash it in axum's
/// shared state as `Arc<dyn Db>`.
pub trait Db: Send + Sync + 'static {
    /// Insert an event. Idempotent by content hash: re-inserting the same
    /// id is a no-op and returns the same id without error.
    fn put_event(&self, ev: &IngestedEvent) -> Result<EventId, DbError>;

    /// Fetch an event by content hash. None if unknown. Does not honor
    /// expiry — that's the list method's job.
    fn get_by_id(&self, id: &EventId) -> Result<Option<StoredEvent>, DbError>;

    /// List events matching the filter, ordered by created_at DESC.
    /// Honors `include_expired` — by default expired events are hidden.
    fn list(&self, filter: &EventFilter) -> Result<Vec<StoredEvent>, DbError>;

    /// Sum of body bytes stored against a coordination key, counted across
    /// both host and joiner roles. Used by Phase 4 quota enforcement.
    fn bytes_stored_by_pubkey(&self, pubkey: &Pubkey) -> Result<u64, DbError>;

    /// Hard-delete events whose `expires_at` is set and <= `now`. Returns
    /// the number of rows removed. Used by a periodic background task in
    /// Phase 4.
    fn delete_expired(&self, now: i64) -> Result<u64, DbError>;

    /// Run SQLite VACUUM. Reclaims free pages.
    fn vacuum(&self) -> Result<(), DbError>;
}
