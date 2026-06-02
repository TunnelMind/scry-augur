// Feodo Tracker Botnet C2 source (abuse.ch).
//
// abuse.ch's curated list of botnet command-and-control servers (Emotet,
// QakBot, Dridex, TrickBot, …). Strong direct indicator: every entry is an
// IP observed acting as malware C2.
//
// Endpoint: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
// License: CC0 (abuse.ch standard) → redistributable=true.
//
// Format: leading `#` comment block, then a CSV header line, then rows:
//   "first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
//   "2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"
//
// Storage: entity_type='ip', entity_value=dst_ip, threat_type='c2'. The
// materializer joins actor source_ip against this directly.

import { execute } from "../db.js";
import { fetchWithCertInfo, checkAndRecordCertFingerprint } from "../lib/cert-fetch.js";

const FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv";
const SOURCE_ID = "feodo";

const IPV4_RE = /^(?:(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])\.){3}(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])$/;

export async function runFeodo() {
  const t0 = Date.now();
  const ua = process.env.AUGUR_UA || "scry-augur/0.1";

  let body;
  try {
    const resp = await fetchWithCertInfo(FEED_URL, {
      headers: { "User-Agent": ua, Accept: "text/plain" },
    });
    await checkAndRecordCertFingerprint(SOURCE_ID, resp);
    if (resp.status !== 200) throw new Error(`feodo HTTP ${resp.status}`);
    body = resp.body;
  } catch (e) {
    await recordSourceError(`fetch failed: ${e.message}`);
    throw e;
  }

  const entries = parseFeodoCsv(body);
  const now = Date.now();
  const allRows = entries.map((e) => buildObservationRow(e, now)).filter(Boolean);

  let promoted = 0;
  const BATCH = 500;
  for (let i = 0; i < allRows.length; i += BATCH) {
    promoted += await batchUpsertObs(allRows.slice(i, i + BATCH));
  }

  await execute(
    `UPDATE infra_sources SET last_run_ms = $1, last_run_rows = $2, last_error = NULL WHERE id = $3`,
    [Date.now(), promoted, SOURCE_ID]
  );
  return { rows: entries.length, promoted, skipped: entries.length - promoted, duration_ms: Date.now() - t0 };
}

async function recordSourceError(msg) {
  await execute(
    `UPDATE infra_sources SET last_run_ms = $1, last_error = $2 WHERE id = $3`,
    [Date.now(), String(msg).slice(0, 500), SOURCE_ID]
  );
}

/**
 * Parse Feodo ipblocklist.csv. Returns array of
 * { dst_ip, dst_port, c2_status, last_online, malware, first_seen_utc }.
 */
export function parseFeodoCsv(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    // skip the header row
    if (line.startsWith('"first_seen_utc"')) continue;
    const fields = (line.match(/"([^"]*)"/g) || []).map((s) => s.slice(1, -1));
    if (fields.length < 6) continue;
    const [first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware] = fields;
    if (!IPV4_RE.test(dst_ip)) continue;
    out.push({ first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware });
  }
  return out;
}

function buildObservationRow(e, nowMs) {
  const tags = ["c2", "feodo"];
  if (e.malware) tags.push(e.malware.toLowerCase());
  if (e.c2_status) tags.push(e.c2_status); // online | offline
  return {
    id: `feodo:${e.dst_ip}:${e.dst_port}`,
    source_id: SOURCE_ID,
    entity_type: "ip",
    entity_value: e.dst_ip,
    threat_type: "c2",
    tags,
    first_seen_ms: nowMs,
    last_seen_ms: nowMs,
    metadata: JSON.stringify({
      dst_port: e.dst_port,
      c2_status: e.c2_status,
      last_online: e.last_online,
      malware: e.malware,
      first_seen_utc: e.first_seen_utc,
    }),
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
      entity_value = EXCLUDED.entity_value,
      tags         = EXCLUDED.tags,
      threat_type  = EXCLUDED.threat_type,
      metadata     = EXCLUDED.metadata
    RETURNING 1`;
  return await execute(sql, params);
}
