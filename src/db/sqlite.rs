use std::path::Path;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{OptionalExtension, params};

use super::{Db, DbError, EventFilter, EventId, EventKind, IngestedEvent, Pubkey, StoredEvent};

const SCHEMA: &str = include_str!("schema.sql");

const PRAGMAS: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = 2;
PRAGMA cache_size = 20000;
PRAGMA mmap_size = 0;
PRAGMA foreign_keys = ON;
";

#[derive(Clone)]
pub struct SqliteDb {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let manager = SqliteConnectionManager::file(path).with_init(|c| {
            c.execute_batch(PRAGMAS)?;
            Ok(())
        });
        let pool = Pool::builder().max_size(8).build(manager)?;
        let conn = pool.get()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { pool })
    }

    /// Open an in-memory database. Used by unit tests.
    pub fn open_in_memory() -> Result<Self, DbError> {
        let manager = SqliteConnectionManager::memory().with_init(|c| {
            c.execute_batch(PRAGMAS)?;
            Ok(())
        });
        // SQLite ":memory:" databases are per-connection, so the pool must
        // be size 1 or every connection sees a fresh empty DB.
        let pool = Pool::builder().max_size(1).build(manager)?;
        let conn = pool.get()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { pool })
    }
}

impl Db for SqliteDb {
    fn put_event(&self, ev: &IngestedEvent) -> Result<EventId, DbError> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO event \
             (id, kind, scheme, host_pubkey, joiner_pubkey, cohort_id, created_at, expires_at, body) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                ev.id.as_bytes().as_slice(),
                ev.kind.as_int(),
                ev.scheme,
                ev.host_pubkey.as_ref().map(|p| p.as_bytes().to_vec()),
                ev.joiner_pubkey.as_ref().map(|p| p.as_bytes().to_vec()),
                ev.cohort_id.as_ref().map(|c| c.as_bytes().to_vec()),
                ev.created_at,
                ev.expires_at,
                ev.body,
            ],
        )?;
        for tag in &ev.tags {
            tx.execute(
                "INSERT OR IGNORE INTO event_tag (event_id, tag) VALUES (?1, ?2)",
                params![ev.id.as_bytes().as_slice(), tag],
            )?;
        }
        tx.commit()?;
        Ok(ev.id)
    }

    fn get_by_id(&self, id: &EventId) -> Result<Option<StoredEvent>, DbError> {
        let conn = self.pool.get()?;
        let row = conn
            .query_row(
                "SELECT id, kind, scheme, host_pubkey, joiner_pubkey, cohort_id, created_at, expires_at, body \
                 FROM event WHERE id = ?1",
                params![id.as_bytes().as_slice()],
                row_to_stored_event,
            )
            .optional()?;
        row.transpose()
    }

    fn list(&self, filter: &EventFilter) -> Result<Vec<StoredEvent>, DbError> {
        let conn = self.pool.get()?;
        let limit = filter.limit.unwrap_or(100).min(1000) as i64;
        let offset = filter.offset.unwrap_or(0) as i64;
        let now = chrono::Utc::now().timestamp();

        let mut stmt = conn.prepare(
            "SELECT id, kind, scheme, host_pubkey, joiner_pubkey, cohort_id, created_at, expires_at, body \
             FROM event \
             WHERE (?1 IS NULL OR kind = ?1) \
               AND (?2 IS NULL OR scheme = ?2) \
               AND (?3 IS NULL OR cohort_id = ?3) \
               AND (?4 IS NULL OR host_pubkey = ?4) \
               AND (?5 IS NULL OR created_at >= ?5) \
               AND (?6 = 1 OR expires_at IS NULL OR expires_at > ?7) \
             ORDER BY created_at DESC \
             LIMIT ?8 OFFSET ?9",
        )?;

        let rows = stmt.query_map(
            params![
                filter.kind.map(|k| k.as_int()),
                filter.scheme.as_deref(),
                filter.cohort_id.as_ref().map(|c| c.as_bytes().to_vec()),
                filter.host_pubkey.as_ref().map(|p| p.as_bytes().to_vec()),
                filter.since,
                if filter.include_expired { 1i64 } else { 0i64 },
                now,
                limit,
                offset,
            ],
            row_to_stored_event,
        )?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    fn bytes_stored_by_pubkey(&self, pubkey: &Pubkey) -> Result<u64, DbError> {
        let conn = self.pool.get()?;
        let pk = pubkey.as_bytes().to_vec();
        let n: i64 = conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(body)), 0) FROM event \
             WHERE host_pubkey = ?1 OR joiner_pubkey = ?1",
            params![pk],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    fn delete_expired(&self, now: i64) -> Result<u64, DbError> {
        let conn = self.pool.get()?;
        let n = conn.execute(
            "DELETE FROM event WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?;
        Ok(n as u64)
    }

    fn vacuum(&self) -> Result<(), DbError> {
        let conn = self.pool.get()?;
        conn.execute_batch("VACUUM")?;
        Ok(())
    }
}

/// Convert a SQLite row into `Result<StoredEvent, DbError>`. Wrapped in
/// `rusqlite::Result` for use with `query_row` / `query_map`.
fn row_to_stored_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<StoredEvent, DbError>> {
    let id_bytes: Vec<u8> = row.get(0)?;
    let kind_int: i64 = row.get(1)?;
    let scheme: String = row.get(2)?;
    let host: Option<Vec<u8>> = row.get(3)?;
    let joiner: Option<Vec<u8>> = row.get(4)?;
    let cohort: Option<Vec<u8>> = row.get(5)?;
    let created_at: i64 = row.get(6)?;
    let expires_at: Option<i64> = row.get(7)?;
    let body: Vec<u8> = row.get(8)?;

    Ok((|| -> Result<StoredEvent, DbError> {
        let id = vec_to_event_id(id_bytes)?;
        let kind =
            EventKind::from_int(kind_int).ok_or(DbError::InvalidStored("unknown event kind"))?;
        let host_pubkey = host.map(vec_to_pubkey).transpose()?;
        let joiner_pubkey = joiner.map(vec_to_pubkey).transpose()?;
        let cohort_id = cohort.map(vec_to_event_id).transpose()?;
        Ok(StoredEvent {
            id,
            kind,
            scheme,
            host_pubkey,
            joiner_pubkey,
            cohort_id,
            created_at,
            expires_at,
            body,
        })
    })())
}

fn vec_to_event_id(v: Vec<u8>) -> Result<EventId, DbError> {
    if v.len() != 32 {
        return Err(DbError::InvalidStored("event id wrong length"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(EventId(a))
}

fn vec_to_pubkey(v: Vec<u8>) -> Result<Pubkey, DbError> {
    if v.len() != 32 {
        return Err(DbError::InvalidStored("pubkey wrong length"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(Pubkey(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> Pubkey {
        Pubkey([byte; 32])
    }

    fn id(byte: u8) -> EventId {
        EventId([byte; 32])
    }

    #[allow(clippy::too_many_arguments)]
    fn make(
        kind: EventKind,
        body: &[u8],
        host: Option<Pubkey>,
        joiner: Option<Pubkey>,
        cohort: Option<EventId>,
        created_at: i64,
        expires_at: Option<i64>,
        tags: Vec<&str>,
    ) -> IngestedEvent {
        IngestedEvent {
            id: EventId::from_body(body),
            kind,
            scheme: "test/v1".into(),
            host_pubkey: host,
            joiner_pubkey: joiner,
            cohort_id: cohort,
            created_at,
            expires_at,
            tags: tags.into_iter().map(String::from).collect(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn open_and_migrate() {
        let db = SqliteDb::open_in_memory().unwrap();
        // Empty list query should succeed even with no rows.
        let v = db.list(&EventFilter::default()).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn put_and_get_round_trip() {
        let db = SqliteDb::open_in_memory().unwrap();
        let ev = make(
            EventKind::Advertisement,
            b"{\"type\":\"advertisement\",\"x\":1}",
            Some(pk(0xaa)),
            None,
            None,
            1_700_000_000,
            None,
            vec!["en", "europe"],
        );
        let returned_id = db.put_event(&ev).unwrap();
        assert_eq!(returned_id, ev.id);

        let fetched = db.get_by_id(&ev.id).unwrap().expect("event must exist");
        assert_eq!(fetched.id, ev.id);
        assert_eq!(fetched.kind, EventKind::Advertisement);
        assert_eq!(fetched.scheme, "test/v1");
        assert_eq!(fetched.host_pubkey, Some(pk(0xaa)));
        assert_eq!(fetched.joiner_pubkey, None);
        assert_eq!(fetched.cohort_id, None);
        assert_eq!(fetched.created_at, 1_700_000_000);
        assert_eq!(fetched.expires_at, None);
        assert_eq!(fetched.body, ev.body);
    }

    #[test]
    fn idempotent_put() {
        let db = SqliteDb::open_in_memory().unwrap();
        let ev = make(
            EventKind::Advertisement,
            b"same body",
            Some(pk(1)),
            None,
            None,
            1,
            None,
            vec![],
        );
        db.put_event(&ev).unwrap();
        // Second insert with the same id is a no-op (returns same id, no error).
        let id2 = db.put_event(&ev).unwrap();
        assert_eq!(id2, ev.id);
        // Verify list returns exactly one row.
        let v = db.list(&EventFilter::default()).unwrap();
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn list_filters_by_kind() {
        let db = SqliteDb::open_in_memory().unwrap();
        db.put_event(&make(
            EventKind::Advertisement,
            b"a1",
            Some(pk(1)),
            None,
            None,
            10,
            None,
            vec![],
        ))
        .unwrap();
        db.put_event(&make(
            EventKind::JoinAttestation,
            b"j1",
            None,
            Some(pk(2)),
            Some(id(1)),
            20,
            None,
            vec![],
        ))
        .unwrap();
        db.put_event(&make(
            EventKind::SealedCohort,
            b"s1",
            Some(pk(1)),
            None,
            Some(id(1)),
            30,
            None,
            vec![],
        ))
        .unwrap();

        let attestations = db
            .list(&EventFilter {
                kind: Some(EventKind::JoinAttestation),
                ..EventFilter::default()
            })
            .unwrap();
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].kind, EventKind::JoinAttestation);
    }

    #[test]
    fn list_filters_by_cohort() {
        let db = SqliteDb::open_in_memory().unwrap();
        let cohort_a = id(0xa1);
        let cohort_b = id(0xb1);
        for (body, cohort) in [
            (b"j1".as_slice(), cohort_a),
            (b"j2".as_slice(), cohort_a),
            (b"j3".as_slice(), cohort_b),
        ] {
            db.put_event(&make(
                EventKind::JoinAttestation,
                body,
                None,
                Some(pk(0x55)),
                Some(cohort),
                10,
                None,
                vec![],
            ))
            .unwrap();
        }
        let v = db
            .list(&EventFilter {
                cohort_id: Some(cohort_a),
                ..EventFilter::default()
            })
            .unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|e| e.cohort_id == Some(cohort_a)));
    }

    #[test]
    fn list_filters_by_since() {
        let db = SqliteDb::open_in_memory().unwrap();
        for (body, ts) in [
            (b"e1".as_slice(), 100i64),
            (b"e2".as_slice(), 200),
            (b"e3".as_slice(), 300),
        ] {
            db.put_event(&make(
                EventKind::Advertisement,
                body,
                Some(pk(1)),
                None,
                None,
                ts,
                None,
                vec![],
            ))
            .unwrap();
        }
        let v = db
            .list(&EventFilter {
                since: Some(200),
                ..EventFilter::default()
            })
            .unwrap();
        assert_eq!(v.len(), 2);
        // Ordered DESC.
        assert_eq!(v[0].created_at, 300);
        assert_eq!(v[1].created_at, 200);
    }

    #[test]
    fn list_pagination() {
        let db = SqliteDb::open_in_memory().unwrap();
        for i in 0u8..10 {
            db.put_event(&make(
                EventKind::Advertisement,
                &[i],
                Some(pk(1)),
                None,
                None,
                100 + i as i64,
                None,
                vec![],
            ))
            .unwrap();
        }
        let page1 = db
            .list(&EventFilter {
                limit: Some(3),
                offset: Some(0),
                ..EventFilter::default()
            })
            .unwrap();
        let page2 = db
            .list(&EventFilter {
                limit: Some(3),
                offset: Some(3),
                ..EventFilter::default()
            })
            .unwrap();
        assert_eq!(page1.len(), 3);
        assert_eq!(page2.len(), 3);
        // Page 1 newer than page 2.
        assert!(page1[0].created_at > page2[0].created_at);
    }

    #[test]
    fn expired_hidden_by_default_visible_with_flag() {
        let db = SqliteDb::open_in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();
        db.put_event(&make(
            EventKind::JoinAttestation,
            b"alive",
            None,
            Some(pk(1)),
            Some(id(1)),
            now - 10,
            Some(now + 3600),
            vec![],
        ))
        .unwrap();
        db.put_event(&make(
            EventKind::JoinAttestation,
            b"expired",
            None,
            Some(pk(1)),
            Some(id(1)),
            now - 100,
            Some(now - 50),
            vec![],
        ))
        .unwrap();

        let default = db.list(&EventFilter::default()).unwrap();
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].body, b"alive");

        let with_expired = db
            .list(&EventFilter {
                include_expired: true,
                ..EventFilter::default()
            })
            .unwrap();
        assert_eq!(with_expired.len(), 2);
    }

    #[test]
    fn delete_expired_removes_only_past_due() {
        let db = SqliteDb::open_in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();
        db.put_event(&make(
            EventKind::JoinAttestation,
            b"keeps",
            None,
            Some(pk(1)),
            Some(id(1)),
            now - 10,
            Some(now + 3600),
            vec![],
        ))
        .unwrap();
        db.put_event(&make(
            EventKind::JoinAttestation,
            b"goes",
            None,
            Some(pk(1)),
            Some(id(1)),
            now - 100,
            Some(now - 50),
            vec![],
        ))
        .unwrap();
        db.put_event(&make(
            EventKind::Advertisement,
            b"never",
            Some(pk(2)),
            None,
            None,
            now - 10,
            None,
            vec![],
        ))
        .unwrap();

        let removed = db.delete_expired(now).unwrap();
        assert_eq!(removed, 1);
        let v = db
            .list(&EventFilter {
                include_expired: true,
                ..EventFilter::default()
            })
            .unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|e| e.body != b"goes"));
    }

    #[test]
    fn bytes_stored_by_pubkey_sums_both_roles() {
        let db = SqliteDb::open_in_memory().unwrap();
        let target = pk(0xee);
        // host
        db.put_event(&make(
            EventKind::Advertisement,
            &[1u8; 100],
            Some(target),
            None,
            None,
            1,
            None,
            vec![],
        ))
        .unwrap();
        // joiner
        db.put_event(&make(
            EventKind::JoinAttestation,
            &[2u8; 50],
            None,
            Some(target),
            Some(id(1)),
            2,
            None,
            vec![],
        ))
        .unwrap();
        // unrelated event
        db.put_event(&make(
            EventKind::Advertisement,
            &[9u8; 999],
            Some(pk(0x11)),
            None,
            None,
            3,
            None,
            vec![],
        ))
        .unwrap();

        let n = db.bytes_stored_by_pubkey(&target).unwrap();
        assert_eq!(n, 150);
    }

    #[test]
    fn tags_inserted_and_cascade_on_delete() {
        let db = SqliteDb::open_in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();
        let ev = make(
            EventKind::Advertisement,
            b"with tags",
            Some(pk(1)),
            None,
            None,
            now - 10,
            Some(now - 1),
            vec!["en", "europe", "evening"],
        );
        db.put_event(&ev).unwrap();

        // Verify tags landed. Scope the borrowed connection so the pool
        // (size 1 for in-memory) is free for the delete_expired call below.
        {
            let conn = db.pool.get().unwrap();
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM event_tag WHERE event_id = ?1",
                    params![ev.id.as_bytes().as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 3);
        }

        // Delete the event; tag rows should cascade.
        db.delete_expired(now).unwrap();

        {
            let conn = db.pool.get().unwrap();
            let n_after: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM event_tag WHERE event_id = ?1",
                    params![ev.id.as_bytes().as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n_after, 0);
        }
    }

    #[test]
    fn vacuum_runs() {
        let db = SqliteDb::open_in_memory().unwrap();
        db.put_event(&make(
            EventKind::Advertisement,
            b"x",
            Some(pk(1)),
            None,
            None,
            1,
            None,
            vec![],
        ))
        .unwrap();
        db.vacuum().unwrap();
    }

    #[test]
    fn open_file_backed_with_tempdir() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("soup.db");
        let db = SqliteDb::open(&path).unwrap();
        db.put_event(&make(
            EventKind::Advertisement,
            b"file backed",
            Some(pk(7)),
            None,
            None,
            1,
            None,
            vec![],
        ))
        .unwrap();
        // Reopen and verify the event survived.
        drop(db);
        let db2 = SqliteDb::open(&path).unwrap();
        let v = db2.list(&EventFilter::default()).unwrap();
        assert_eq!(v.len(), 1);
    }
}
