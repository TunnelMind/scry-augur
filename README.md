# scry-augur

> **Part of TunnelMind — the intelligence layer agents call before they trust the internet.**
> Three lenses on one signed corpus: **Scry** (*who is attacking?*) · **Sigil** (*who can you trust?*) · **Tracker Data API** (*who is watching?*).
> This repo serves: **Scry** — enriches the Scry actor graph with public threat-intel joins. See [tunnelmind.ai](https://tunnelmind.ai).

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

## Sources

| Source | Endpoint | License | Notes |
|--------|----------|---------|-------|
| URLhaus | `https://urlhaus.abuse.ch/downloads/csv_recent/` | CC0 | CSV, anonymous, ~28k rows / cycle |
| ThreatFox | `https://threatfox.abuse.ch/export/json/recent/` | CC0 | Static bulk JSON dump (anonymous). The POST API requires an Auth-Key as of 2025-01-01; we use the bulk dump instead. |

Materializer joins actors↔infra on IP equality and promotes observations
to `defender_promoted=1` when ≥2 sources agree on the same threat class
(`hostile`, `tor_exit`, `scanner`, `netblock`).

Smoke tests: `scripts/smoke-urlhaus.js`, `scripts/smoke-threatfox.js`.

## To add next

- Tor Project exit list (public, no auth)
- Spamhaus DROP/EDROP (free non-commercial)
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
