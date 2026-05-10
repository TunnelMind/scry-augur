// Tor Project exit list source.
//
// Single text file: one IPv4 (or IPv6) per line, no header, no
// timestamps. Refreshed by torproject.org as exits join/leave the
// network.
//
// Endpoint: https://check.torproject.org/torbulkexitlist
// License: public.
//
// Threat class: `tor_exit` — its own class in the materializer's
// promotion rule. Will NOT promote alongside hostile-class sources
// (URLhaus, ThreatFox); that's intentional. Tor exit-ness and
// malware-distribution-ness are different facts about an IP. A second
// tor source (e.g., dan.me.uk's onionoo cache) would unlock
// ≥2-source promotion within `tor_exit`.
//
// Re-pull behavior: the upsert preserves first_seen_ms (the time we
// first saw an IP in the list) and advances last_seen_ms each cycle.
// Drop-offs are not removed — historical "this IP was a tor exit
// during window X" is the value, and Tor exit churn is meaningful
// signal.

import { execute } from "../db.js";
import { fetchWithCertInfo, checkAndRecordCertFingerprint } from "../lib/cert-fetch.js";

const FEED_URL = "https://check.torproject.org/torbulkexitlist";
const SOURCE_ID = "tor_exit";

export async function runTorExit() {
  const t0 = Date.now();
  const ua = process.env.AUGUR_UA || "scry-augur/0.1";

  let body;
  try {
    const resp = await fetchWithCertInfo(FEED_URL, {
      headers: { "User-Agent": ua, Accept: "text/plain" },
    });
    await checkAndRecordCertFingerprint(SOURCE_ID, resp);
    if (resp.status !== 200) {
      throw new Error(`tor_exit HTTP ${resp.status}`);
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
const IPV6_RE = /^[0-9a-fA-F:]+$/;

/**
 * Parse the bulk exit list. One IP per line. Tolerate blank lines and
 * comment lines (`#`). torproject.org publishes IPv4-only as of
 * writing, but accept IPv6 if it ever appears — schema treats both as
 * `entity_type='ip'`.
 */
export function parseExitList(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (IPV4_RE.test(line) || (line.includes(":") && IPV6_RE.test(line))) {
      out.push(line);
    }
  }
  return out;
}

function buildObservationRow(ip, nowMs) {
  return {
    id: `tor_exit:${ip}`,
    source_id: SOURCE_ID,
    entity_type: "ip",
    entity_value: ip,
    threat_type: "tor_exit",
    tags: ["tor_exit"],
    first_seen_ms: nowMs,
    last_seen_ms: nowMs,
    metadata: JSON.stringify({ feed: "torbulkexitlist" }),
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
  // first_seen_ms is intentionally NOT in the UPDATE clause — preserve
  // the time we first observed this IP in the list, advance last_seen_ms.
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
