#!/usr/bin/env bash
# Remote half of ship-p40-augur.sh (P40 Phase 4.3 — Feodo + Emerging Threats
# as scry-augur source plugins). Rsync'd script, not a heredoc.
set -euo pipefail

cd /opt/tunnelmind/deploy

echo "== applying scry-augur schema/006_feodo_et_sources.sql =="
docker exec -i tmd-postgres psql -U scry -d scry \
  < /opt/tunnelmind/scry-augur/schema/006_feodo_et_sources.sql

echo
echo "== confirming both sources registered in infra_sources =="
docker exec -i tmd-postgres psql -U scry -d scry -At \
  -c "SELECT id, intent, redistributable FROM infra_sources WHERE id IN ('feodo','emerging_threats') ORDER BY id;" < /dev/null

echo
echo "== rebuilding + recreating tmd-scry-augur (code COPY'd into image) =="
docker compose build scry-augur </dev/null
docker compose up -d --force-recreate scry-augur </dev/null

echo
echo "== augur runs a cycle on startup; polling for feodo + ET results (≤120s) =="
OK=0
for i in $(seq 1 24); do
  sleep 5
  ROWS=$(docker exec -i tmd-postgres psql -U scry -d scry -At \
    -c "SELECT id||':'||COALESCE(last_run_rows::text,'pending') FROM infra_sources WHERE id IN ('feodo','emerging_threats') ORDER BY id;" < /dev/null | tr '\n' ' ')
  echo "  [$((i*5))s] $ROWS"
  # both populated with a numeric last_run_rows?
  FEODO=$(docker exec -i tmd-postgres psql -U scry -d scry -At -c "SELECT last_run_rows FROM infra_sources WHERE id='feodo';" < /dev/null)
  ET=$(docker exec -i tmd-postgres psql -U scry -d scry -At -c "SELECT last_run_rows FROM infra_sources WHERE id='emerging_threats';" < /dev/null)
  if [[ -n "$FEODO" && -n "$ET" ]]; then OK=1; break; fi
done

echo
echo "== infra_observations counts for the new sources =="
docker exec -i tmd-postgres psql -U scry -d scry -c \
  "SELECT source_id, count(*) FROM infra_observations WHERE source_id IN ('feodo','emerging_threats') GROUP BY 1 ORDER BY 1;" < /dev/null

if [[ "$OK" != "1" ]]; then
  echo "  ⚠️  sources not yet populated after 120s — they will run on the next 30-min cycle."
  echo "      (crtsh in the same cycle can be slow; feodo/ET are independent.)"
  docker logs --tail 20 tmd-scry-augur 2>&1 | grep -iE 'feodo|emerging|error' || true
else
  echo "  ✅ feodo=$FEODO  emerging_threats=$ET rows ingested"
fi

echo
echo "== P40 Phase 4.3 (Augur feeds) remote sequence complete. =="
