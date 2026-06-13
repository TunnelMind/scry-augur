#!/usr/bin/env bash
# Ship IPv6 threat-feed ingest to the VPS (feat/ipv6-support). No schema change.
#
# Run from BEAST with the SSH key loaded:
#   eval $(ssh-agent -s) && ssh-add ~/.ssh/id_ed25519 && \
#     /home/o2k/scry-augur/deploy/ship-ipv6.sh
#
# What this does:
#   1. rsync scry-augur tree to /opt/tunnelmind/scry-augur on the VPS
#   2. Rebuild + recreate tmd-scry-augur (code is COPY'd into the image)
#   3. Poll for the spamhaus_drop cycle (now also ingesting DROPv6)
set -euo pipefail

VPS=${VPS:-root@178.104.110.11}
LOCAL_AUGUR=/home/o2k/scry-augur

echo "== rsync scry-augur → VPS =="
rsync -a --delete \
  --exclude node_modules --exclude .git \
  "$LOCAL_AUGUR/" "$VPS:/opt/tunnelmind/scry-augur/"

ssh "$VPS" 'bash -se' <<'REMOTE'
set -euo pipefail
cd /opt/tunnelmind/deploy

echo "== rebuilding + recreating tmd-scry-augur =="
docker compose build scry-augur </dev/null
docker compose up -d --force-recreate scry-augur </dev/null

echo "== augur runs a cycle on startup; polling spamhaus_drop (≤120s) =="
for i in $(seq 1 24); do
  sleep 5
  ROWS=$(docker exec -i tmd-postgres psql -U scry -d scry -At \
    -c "SELECT COALESCE(last_run_rows::text,'pending') FROM infra_sources WHERE id='spamhaus_drop';" < /dev/null)
  echo "  [$((i*5))s] spamhaus_drop=$ROWS"
  [[ -n "$ROWS" && "$ROWS" != "pending" ]] && break
done

echo "== count any v6 CIDRs now in infra_observations (contain a colon) =="
docker exec -i tmd-postgres psql -U scry -d scry -At \
  -c "SELECT count(*) FROM infra_observations WHERE source_id='spamhaus_drop' AND entity_type='cidr' AND entity_value LIKE '%:%';" < /dev/null \
  | xargs -I{} echo "  spamhaus DROPv6 CIDRs ingested: {}"

echo "== recent augur log lines (errors, if any) =="
docker logs --tail 15 tmd-scry-augur 2>&1 | grep -iE 'spamhaus|error|drop' || true
REMOTE

echo
echo "== done. scry-augur now ingests IPv6 indicators (DROPv6 + ThreatFox/URLhaus v6). =="
