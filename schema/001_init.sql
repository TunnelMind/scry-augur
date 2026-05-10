-- scry-augur schema (Phase 2a — clearnet recon enricher).
--
-- Three tables added to the existing `scry` PG database. No separate
-- database; Augur joins directly with scry-server's actor graph.
--
-- Apply with: psql ... -f schema/001_init.sql

BEGIN;

-- One row per data feed Augur consumes.
CREATE TABLE IF NOT EXISTS infra_sources (
    id              TEXT PRIMARY KEY,         -- 'urlhaus', 'threatfox', 'crtsh', 'rdap', 'tor_exit'
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    license         TEXT NOT NULL,            -- per the source's terms; see README
    redistributable BOOLEAN NOT NULL,         -- true → can surface to free-tier API consumers
    last_run_ms     BIGINT,
    last_run_rows   INTEGER,
    last_error      TEXT
);

-- Each fact pulled from a source.
CREATE TABLE IF NOT EXISTS infra_observations (
    id              TEXT PRIMARY KEY,         -- '<source>:<source-row-id>' or content hash
    source_id       TEXT NOT NULL REFERENCES infra_sources(id),
    entity_type     TEXT NOT NULL CHECK (entity_type IN ('ip','domain','url','sha256','asn')),
    entity_value    TEXT NOT NULL,
    threat_type     TEXT,                     -- 'c2','malware_dl','phishing','spam','tor_exit','scanner','unknown'
    tags            TEXT[],                   -- free-form, source-defined
    first_seen_ms   BIGINT NOT NULL,
    last_seen_ms    BIGINT NOT NULL,
    expires_at_ms   BIGINT,                   -- if the source publishes an expiry
    metadata        JSONB                     -- raw source fields not promoted to first-class columns
);
CREATE INDEX IF NOT EXISTS idx_infra_obs_entity ON infra_observations(entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_infra_obs_source ON infra_observations(source_id);
CREATE INDEX IF NOT EXISTS idx_infra_obs_recent ON infra_observations(last_seen_ms DESC);
CREATE INDEX IF NOT EXISTS idx_infra_obs_threat  ON infra_observations(threat_type);

-- Materialized join: when an actor's source_ip also appears in
-- infra_observations.entity_value (with entity_type='ip'), link them.
-- Built by Augur's own materializer on a 30-min cron, AFTER source pulls.
CREATE TABLE IF NOT EXISTS actor_infra_links (
    actor_id        TEXT NOT NULL,
    infra_obs_id    TEXT NOT NULL,
    matched_at_ms   BIGINT NOT NULL,
    PRIMARY KEY (actor_id, infra_obs_id)
);
CREATE INDEX IF NOT EXISTS idx_actor_infra_links_obs ON actor_infra_links(infra_obs_id);

-- Seed sources we plan to support. The runtime upserts these on first run
-- but seeding here documents the intended source list.
INSERT INTO infra_sources (id, name, url, license, redistributable) VALUES
    ('urlhaus', 'URLhaus (abuse.ch)', 'https://urlhaus.abuse.ch/downloads/csv_recent/', 'CC0', true),
    ('threatfox', 'ThreatFox (abuse.ch)', 'https://threatfox.abuse.ch/export/json/recent/', 'CC0', true),
    ('tor_exit', 'Tor Project exit list', 'https://check.torproject.org/torbulkexitlist', 'public', true),
    ('spamhaus_drop', 'Spamhaus DROP', 'https://www.spamhaus.org/drop/drop.txt', 'free non-commercial', false),
    ('crtsh', 'crt.sh CT log search', 'https://crt.sh', 'public', true)
ON CONFLICT (id) DO NOTHING;

COMMIT;
