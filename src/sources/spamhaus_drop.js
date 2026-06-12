// Spamhaus DROP source.
//
// "Don't Route Or Peer" — Spamhaus's manually-curated list of CIDRs
// that should never originate or transit legitimate traffic. Strong
// signal: every entry is a netblock Spamhaus considers fully hijacked
// or operated by a known bad actor.
//
// Endpoint: https://www.spamhaus.org/drop/drop.txt
// License: free for non-commercial use; redistribution prohibited.
// `infra_sources.redistributable=false` for this source — the count
// surfaces in `enrichment_count` but the source name is NEVER returned
// in `enrichment_sources` to API consumers.
//
// Format:
//   ; Spamhaus DROP List YYYY/MM/DD
//   ; <preamble>
//   5.42.184.0/22 ; SBL537404
//   14.0.16.0/20 ; SBL512081
//
// Lines starting with `;` are comments. Each data line is
// `<CIDR> ; SBL<id>` with optional whitespace around the separator.
//
// Storage: entity_type='cidr', entity_value=<CIDR>. Materializer joins
// actor source_ip against CIDR via inet `<<=` operator.

import { execute } from "../db.js";
import { fetchWithCertInfo, checkAndRecordCertFingerprint } from "../lib/cert-fetch.js";
import { isV6Cidr } from "../lib/ipv6.js";

const FEED_URL = "https://www.spamhaus.org/drop/drop.txt";
const FEED_URL_V6 = "https://www.spamhaus.org/drop/dropv6.txt";
const SOURCE_ID = "spamhaus_drop";

export async function runSpamhausDrop() {
  const t0 = Date.now();
  const ua = process.env.AUGUR_UA || "scry-augur/0.1";

  let body, bodyV6 = "";
  try {
    const resp = await fetchWithCertInfo(FEED_URL, {
      headers: { "User-Agent": ua, Accept: "text/plain" },
    });
    await checkAndRecordCertFingerprint(SOURCE_ID, resp);
    if (resp.status !== 200) {
      throw new Error(`spamhaus_drop HTTP ${resp.status}`);
    }
    body = resp.body;
  } catch (e) {
    await recordSourceError(`fetch failed: ${e.message}`);
    throw e;
  }

  // DROPv6 is a separate list; a v6 fetch failure must NOT sink the v4 run.
  try {
    const respV6 = await fetchWithCertInfo(FEED_URL_V6, {
      headers: { "User-Agent": ua, Accept: "text/plain" },
    });
    if (respV6.status === 200) bodyV6 = respV6.body;
  } catch {
    /* best-effort — v4 list already loaded */
  }

  const entries = [...parseDropList(body), ...parseDropList(bodyV6)];
  const now = Date.now();
  const allRows = entries
    .map((e) => buildObservationRow(e, now))
    .filter(Boolean);

  let promoted = 0;
  const BATCH = 500;
  for (let i = 0; i < allRows.length; i += BATCH) {
    promoted += await batchUpsertObs(allRows.slice(i, i + BATCH));
  }
  const skipped = entries.length - promoted;

  await execute(
    `UPDATE infra_sources
        SET last_run_ms = $1, last_run_rows = $2, last_error = NULL
      WHERE id = $3`,
    [Date.now(), promoted, SOURCE_ID]
  );

  return { rows: entries.length, promoted, skipped, duration_ms: Date.now() - t0 };
}

async function recordSourceError(msg) {
  await execute(
    `UPDATE infra_sources
        SET last_run_ms = $1, last_error = $2
      WHERE id = $3`,
    [Date.now(), String(msg).slice(0, 500), SOURCE_ID]
  );
}

// First whitespace-delimited token before `; SBL<id>` — a v4 or v6 CIDR.
const DROP_LINE_RE = /^(\S+)\s*;\s*(SBL\d+)/;
const CIDR_V4_RE = /^(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])(?:\.(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])){3}\/\d{1,2}$/;

/**
 * Parse drop.txt / dropv6.txt (same line format). Returns array of
 * { cidr, sbl_id }. v6 CIDRs are validated via isV6Cidr so a malformed
 * value never reaches the materializer's `entity_value::inet` cast.
 */
export function parseDropList(text) {
  if (!text) return [];
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith(";")) continue;
    const m = line.match(DROP_LINE_RE);
    if (!m) continue;
    const [, cidr, sbl] = m;
    if (!CIDR_V4_RE.test(cidr) && !isV6Cidr(cidr)) continue;
    out.push({ cidr, sbl_id: sbl });
  }
  return out;
}

function buildObservationRow(entry, nowMs) {
  return {
    id: `spamhaus_drop:${entry.sbl_id}`,
    source_id: SOURCE_ID,
    entity_type: "cidr",
    entity_value: entry.cidr,
    threat_type: "netblock_blocked",
    tags: ["netblock", "spamhaus_drop"],
    first_seen_ms: nowMs,
    last_seen_ms: nowMs,
    metadata: JSON.stringify({ sbl_id: entry.sbl_id }),
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
  // first_seen_ms preserved on conflict (only set on initial insert).
  const sql = `
    INSERT INTO infra_observations
      (id, source_id, entity_type, entity_value, threat_type, tags,
       first_seen_ms, last_seen_ms, metadata)
    VALUES ${placeholders.join(", ")}
    ON CONFLICT (id) DO UPDATE SET
      last_seen_ms  = GREATEST(infra_observations.last_seen_ms, EXCLUDED.last_seen_ms),
      entity_value  = EXCLUDED.entity_value,
      tags          = EXCLUDED.tags,
      threat_type   = EXCLUDED.threat_type,
      metadata      = EXCLUDED.metadata
    RETURNING 1`;
  return await execute(sql, params);
}
