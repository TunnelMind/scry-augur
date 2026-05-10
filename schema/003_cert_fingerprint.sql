-- Per-source TLS public-key fingerprint tracking. Lets us alert when a
-- source's cert key rotates (legitimate or otherwise). Red-team round-2
-- AI-X2 (light): not full pinning, just change-detection.

ALTER TABLE infra_sources
  ADD COLUMN IF NOT EXISTS last_seen_spki_sha256 TEXT,
  ADD COLUMN IF NOT EXISTS last_seen_spki_at_ms  BIGINT;
