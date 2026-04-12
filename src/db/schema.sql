CREATE TABLE IF NOT EXISTS event (
    id            BLOB PRIMARY KEY,
    kind          INTEGER NOT NULL,
    scheme        TEXT NOT NULL,
    host_pubkey   BLOB,
    joiner_pubkey BLOB,
    cohort_id     BLOB,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    body          BLOB NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS event_kind_created  ON event(kind, created_at DESC);
CREATE INDEX IF NOT EXISTS event_cohort_kind   ON event(cohort_id, kind);
CREATE INDEX IF NOT EXISTS event_host_created  ON event(host_pubkey, created_at DESC);
CREATE INDEX IF NOT EXISTS event_scheme_kind   ON event(scheme, kind, created_at DESC);

CREATE TABLE IF NOT EXISTS event_tag (
    event_id BLOB NOT NULL REFERENCES event(id) ON DELETE CASCADE,
    tag      TEXT NOT NULL,
    PRIMARY KEY (event_id, tag)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS event_tag_value ON event_tag(tag);
