-- Defender-tier promotion column. Red-team fix M5.
--
-- An infra_observation is "defender_promoted" only when ≥2 distinct
-- sources independently agree on the same (entity_type, entity_value).
-- Single-source claims stay in the corpus for free-tier "enrichment_count"
-- but don't surface as authoritative defender-tier facts. Defends against
-- adversarial source poisoning where an attacker submits a false report
-- to one feed (URLhaus / ThreatFox / etc) to manipulate the actor graph.
--
-- The materializer flips this on a recurring pass; see scry-augur/src/materializer.js.

ALTER TABLE infra_observations
  ADD COLUMN IF NOT EXISTS defender_promoted SMALLINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_infra_obs_promoted
  ON infra_observations(entity_type, entity_value)
  WHERE defender_promoted = 1;
