// Emerging Threats — compromised IPs source.
//
// Proofpoint/Emerging Threats' open list of currently-compromised hosts
// (boxes confirmed participating in attacks). Direct indicator.
//
// Endpoint: https://rules.emergingthreats.net/blockrules/compromised-ips.txt
// License: Emerging Threats open ruleset (BSD-style) → redistributable=true.
//
// Format: one IPv4 per line, no header. (Occasional `#` comment lines are
// tolerated and skipped.)
//
// Storage: entity_type='ip', threat_type='compromised_host'. The materializer
// joins actor source_ip against this directly.

import { execute } from "../db.js";
import { fetchWithCertInfo, checkAndRecordCertFingerprint } from "../lib/cert-fetch.js";

const FEED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt";
const SOURCE_ID = "emerging_threats";

const IPV4_RE = /^(?:(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])\.){3}(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])$/;

export async function runEmergingThreats() {
  const t0 = Date.now();
  const ua = process.env.AUGUR_UA || "scry-augur/0.1";

  let body;
  try {
    const resp = await fetchWithCertInfo(FEED_URL, {
      headers: { "User-Agent": ua, Accept: "text/plain" },
    });
    await checkAndRecordCertFingerprint(SOURCE_ID, resp);
    if (resp.status !== 200) throw new Error(`emerging_threats HTTP ${resp.status}`);
    body = resp.body;
  } catch (e) {
    await recordSourceError(`fetch failed: ${e.message}`);
    throw e;
  }

  const ips = parseIpList(body);
  const now = Date.now();
  const allRows = ips.map((ip) => buildObservationRow(ip, now));

  let promoted = 0;
  const BATCH = 500;
  for (let i = 0; i < allRows.length; i += BATCH) {
    promoted += await batchUpsertObs(allRows.slice(i, i + BATCH));
  }

  await execute(
    `UPDATE infra_sources SET last_run_ms = $1, last_run_rows = $2, last_error = NULL WHERE id = $3`,
    [Date.now(), promoted, SOURCE_ID]
  );
  return { rows: ips.length, promoted, skipped: ips.length - promoted, duration_ms: Date.now() - t0 };
}

async function recordSourceError(msg) {
  await execute(
    `UPDATE infra_sources SET last_run_ms = $1, last_error = $2 WHERE id = $3`,
    [Date.now(), String(msg).slice(0, 500), SOURCE_ID]
  );
}

/** Parse a plain one-IP-per-line list. Skips blanks and `#` comments. */
export function parseIpList(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (!IPV4_RE.test(line)) continue;
    out.push(line);
  }
  return out;
}

function buildObservationRow(ip, nowMs) {
  return {
    id: `emerging_threats:${ip}`,
    source_id: SOURCE_ID,
    entity_type: "ip",
    entity_value: ip,
    threat_type: "compromised_host",
    tags: ["compromised", "emerging_threats"],
    first_seen_ms: nowMs,
    last_seen_ms: nowMs,
    metadata: null,
  };
}

async function batchUpsertObs(rowsChunk) {
  if (rowsChunk.length === 0) return 0;
  const cols = 9;
  const placeholders = [];
  const params = [];
  rowsChunk.forEach((r, i) => {
    const base = i * cols;
    placeholders.push(
      `($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6}::text[], $${base + 7}, $${base + 8}, $${base + 9}::jsonb)`
    );
    params.push(
      r.id, r.source_id, r.entity_type, r.entity_value, r.threat_type,
      r.tags, r.first_seen_ms, r.last_seen_ms, r.metadata
    );
  });
  const sql = `
    INSERT INTO infra_observations
      (id, source_id, entity_type, entity_value, threat_type, tags,
       first_seen_ms, last_seen_ms, metadata)
    VALUES ${placeholders.join(", ")}
    ON CONFLICT (id) DO UPDATE SET
      last_seen_ms = GREATEST(infra_observations.last_seen_ms, EXCLUDED.last_seen_ms),
      tags         = EXCLUDED.tags,
      threat_type  = EXCLUDED.threat_type
    RETURNING 1`;
  return await execute(sql, params);
}
