// Second tor exit list — dan.me.uk.
//
// Independent from check.torproject.org's bulk list. Having two tor
// sources unlocks ≥2-source promotion within the `tor_exit` class
// (materializer rule M5/AI-X1 fires on COUNT(DISTINCT source_id) >= 2).
// dan.me.uk publishes a slightly different view: includes nodes with
// the Exit flag set in the past 30 days, vs. torproject.org's "currently
// in the consensus".
//
// Endpoint: https://www.dan.me.uk/torlist/
// License: free public.
// **Rate limit:** dan.me.uk caps fetches to once per 30 minutes per IP;
// our SOURCE_INTERVAL_MS default (1800000ms) matches exactly. Don't
// invoke this source more often than that — they 503 abusive clients.

import { execute } from "../db.js";
import { fetchWithCertInfo, checkAndRecordCertFingerprint } from "../lib/cert-fetch.js";

const FEED_URL = "https://www.dan.me.uk/torlist/";
const SOURCE_ID = "tor_dan";

export async function runTorDan() {
  const t0 = Date.now();
  const ua = process.env.AUGUR_UA || "scry-augur/0.1";

  let body;
  try {
    const resp = await fetchWithCertInfo(FEED_URL, {
      headers: { "User-Agent": ua, Accept: "text/plain" },
    });
    await checkAndRecordCertFingerprint(SOURCE_ID, resp);
    if (resp.status !== 200) {
      throw new Error(`tor_dan HTTP ${resp.status}` + (resp.status === 503 ? " (rate-limited — too-frequent fetch?)" : ""));
    }
    body = resp.body;
  } catch (e) {
    await recordSourceError(`fetch failed: ${e.message}`);
    throw e;
  }

  const ips = parseExitList(body);
  const now = Date.now();
  const allRows = ips.map((ip) => buildObservationRow(ip, now));

  let promoted = 0;
  const BATCH = 500;
  for (let i = 0; i < allRows.length; i += BATCH) {
    promoted += await batchUpsertObs(allRows.slice(i, i + BATCH));
  }
  const skipped = allRows.length - promoted;

  await execute(
    `UPDATE infra_sources
        SET last_run_ms = $1, last_run_rows = $2, last_error = NULL
      WHERE id = $3`,
    [Date.now(), promoted, SOURCE_ID]
  );

  return { rows: ips.length, promoted, skipped, duration_ms: Date.now() - t0 };
}

async function recordSourceError(msg) {
  await execute(
    `UPDATE infra_sources
        SET last_run_ms = $1, last_error = $2
      WHERE id = $3`,
    [Date.now(), String(msg).slice(0, 500), SOURCE_ID]
  );
}

const IPV4_RE = /^(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])(?:\.(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])){3}$/;

export function parseExitList(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (IPV4_RE.test(line)) out.push(line);
  }
  return out;
}

function buildObservationRow(ip, nowMs) {
  return {
    id: `tor_dan:${ip}`,
    source_id: SOURCE_ID,
    entity_type: "ip",
    entity_value: ip,
    threat_type: "tor_exit",
    tags: ["tor_exit"],
    first_seen_ms: nowMs,
    last_seen_ms: nowMs,
    metadata: JSON.stringify({ feed: "dan.me.uk/torlist" }),
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
      threat_type  = EXCLUDED.threat_type,
      metadata     = EXCLUDED.metadata
    RETURNING 1`;
  return await execute(sql, params);
}
