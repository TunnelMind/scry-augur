-- 005_source_intent.sql
--
-- Adds an `intent` discriminator to infra_sources so direct-indicator queries
-- can filter discovery feeds out by joining on intent, instead of every caller
-- hardcoding an exclusion array (e.g. NON_THREAT_SOURCES = ['crtsh'] in
-- scry-server/src/routes/check_domain.js).
--
-- Intent values:
--   threat_feed — direct indicator of malicious activity (URLhaus, ThreatFox, …)
--   discovery   — useful for entity expansion, not for malice attribution (crt.sh CT logs)
--   noise       — ingested for completeness, do not count toward verdicts
--
-- Default is threat_feed so any source created without an explicit intent
-- counts as direct-indicator data (the conservative choice). crtsh is the
-- single discovery source today; flip it explicitly.
--
-- Roadmap: project_tunnelmind_roadmap.md item #32 / project_augur_intent_column.

BEGIN;

ALTER TABLE infra_sources
  ADD COLUMN IF NOT EXISTS intent TEXT NOT NULL DEFAULT 'threat_feed'
  CHECK (intent IN ('threat_feed', 'discovery', 'noise'));

UPDATE infra_sources SET intent = 'discovery' WHERE id = 'crtsh';

COMMIT;
