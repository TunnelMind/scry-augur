-- 006_feodo_et_sources.sql — P40 Phase 4.3.
--
-- Register two new direct-indicator IP feeds. Both are entity_type='ip',
-- intent defaults to 'threat_feed' (the conservative default from 005), so
-- they count toward /v1/check verdicts via the existing augur.enrichment
-- path — no new table, no new cross-ref code (eat-own-dogfood: scry-augur
-- already IS the threat-feed engine).
--
-- Apply with: docker exec -i tmd-postgres psql -U scry -d scry < schema/006_feodo_et_sources.sql

BEGIN;

INSERT INTO infra_sources (id, name, url, license, redistributable) VALUES
  ('feodo', 'Feodo Tracker Botnet C2 (abuse.ch)',
   'https://feodotracker.abuse.ch/downloads/ipblocklist.csv', 'CC0', true),
  ('emerging_threats', 'Emerging Threats compromised IPs',
   'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
   'Emerging Threats open (BSD)', true)
ON CONFLICT (id) DO NOTHING;

COMMIT;
