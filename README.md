# scry-augur

Clearnet recon enricher for the Scry actor graph (P22, Phase 2a).

Augur is a **passive aggregator** of public threat-intel feeds — URLhaus,
ThreatFox, the Tor exit list, Spamhaus, CT logs. It joins what other
defenders have already published about an IP/domain/URL with what
Familiar has independently observed of that same entity, and surfaces
the join via two new tables in the Scry corpus.

**Hard rule: Augur is not an active prober.** It does not connect to
attacker infrastructure, does not re-fetch reported URLs to confirm
they're live, does not scan ports, does not resolve attacker domains.
Every data point comes from an already-public feed.

Full design: `TunnelMind/docs/AUGUR-DESIGN-2026-05.md` in the vault.

## Tables

Three new tables in the existing `scry` PG database (no separate DB —
Augur joins directly with scry-server's `actors`):

- `infra_sources` — one row per feed (URLhaus, ThreatFox, …)
- `infra_observations` — facts pulled from sources, keyed by entity (ip/domain/url/sha256/asn)
- `actor_infra_links` — materialized join (actor_id × infra_obs_id) where actor IPs match infra IPs

Schema in `schema/001_init.sql`.

## v0.1 (this commit)

- URLhaus only. CSV pull every 30 min, ON-CONFLICT-update on re-runs.
- Materializer joins actors↔infra on IP equality.
- Smoke test in `scripts/smoke-urlhaus.js`.

## To add next

- ThreatFox (JSON API, stronger taxonomy)
- Tor Project exit list
- Spamhaus DROP/EDROP
- crt.sh CT-log search
- `enrichment_count` column on scry-server's `/v1/check/{ip}` response

## Run

```bash
# Schema (once, against the live VPS Postgres)
ssh -fN -L 15432:127.0.0.1:5432 root@178.104.110.11
PG_URL="postgresql://scry:$(ssh root@178.104.110.11 'grep ^TUNNELMIND_PG_PASSWORD= /opt/tunnelmind/deploy/.env | cut -d= -f2')@127.0.0.1:15432/scry" \
  psql -f schema/001_init.sql

# Smoke
PG_URL="..." npm run smoke:urlhaus

# Production loop (later, on the VPS)
PG_URL="..." npm start
```
