-- Allow `cidr` as an entity_type in infra_observations. Spamhaus DROP /
-- EDROP publish CIDRs (e.g. `5.42.184.0/22`), and the materializer joins
-- actor source_ips against them via `source_ip::inet <<= entity_value::inet`.
-- The check.js enrichment query also extends to CIDR matches.
--
-- The original CHECK constraint was added in 001_init.sql. Postgres
-- doesn't support `ALTER ... DROP CHECK` by inferred name reliably, so
-- we drop by the auto-generated name (verified via \d+ infra_observations).

BEGIN;

DO $$
DECLARE
  cname TEXT;
BEGIN
  SELECT con.conname INTO cname
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
   WHERE rel.relname = 'infra_observations'
     AND con.contype = 'c'
     AND pg_get_constraintdef(con.oid) LIKE '%entity_type%';
  IF cname IS NOT NULL THEN
    EXECUTE format('ALTER TABLE infra_observations DROP CONSTRAINT %I', cname);
  END IF;
END $$;

ALTER TABLE infra_observations
  ADD CONSTRAINT infra_observations_entity_type_check
  CHECK (entity_type IN ('ip','cidr','domain','url','sha256','asn'));

-- Seed the tor_dan row for live DBs that already had 001_init.sql applied
-- (ON CONFLICT DO NOTHING on the original seed wouldn't add new rows).
INSERT INTO infra_sources (id, name, url, license, redistributable) VALUES
    ('tor_dan', 'Tor exit list (dan.me.uk)', 'https://www.dan.me.uk/torlist/', 'public', true)
ON CONFLICT (id) DO NOTHING;

COMMIT;
