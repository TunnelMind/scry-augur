// URLhaus (abuse.ch) source.
//
// Public CSV: https://urlhaus.abuse.ch/downloads/csv_recent/
// License: CC0. Redistributable.
//
// CSV format (after the # header lines):
//   "id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"
//
// We extract the URL and resolve it to (entity_type=ip, entity_value=X) when
// the URL contains an IP literal, OR (entity_type=domain, entity_value=X) when
// it contains a hostname. We also keep the URL itself as a separate
// entity_type=url row so consumers can correlate by URL too.
//
// Hard rule: never re-fetch the URL. URLhaus tells us the URL exists; that's
// enough. Confirming it's still live would make us an active prober.

import { execute } from "../db.js";

const URL_FEED = "https://urlhaus.abuse.ch/downloads/csv_recent/";
const SOURCE_ID = "urlhaus";

export async function runUrlhaus() {
  const t0 = Date.now();
  const ua = process.env.AUGUR_UA || "scry-augur/0.1";

  let csvText;
  try {
    const resp = await fetch(URL_FEED, {
      headers: { "User-Agent": ua, Accept: "text/csv" },
    });
    if (!resp.ok) throw new Error(`urlhaus fetch ${resp.status}`);
    csvText = await resp.text();
  } catch (e) {
    await recordSourceError(`fetch failed: ${e.message}`);
    throw e;
  }

  const rows = parseCsv(csvText);

  // Build all observation row-objects first, then upsert in batches.
  // Per-row INSERT round-trips dominate runtime over a remote PG (SSH
  // tunnel from BEAST or even the docker bridge from the VPS) once the
  // feed has thousands of rows. Multi-row INSERT...ON CONFLICT cuts ~28k
  // upserts from ~10 min to under 30 seconds.
  const allRows = [];
  for (const r of rows) {
    for (const obs of buildObservationRows(r)) allRows.push(obs);
  }

  let promoted = 0;
  const BATCH = 500;
  for (let i = 0; i < allRows.length; i += BATCH) {
    promoted += await batchUpsertObs(allRows.slice(i, i + BATCH));
  }
  const skipped = allRows.length - promoted;

  const durationMs = Date.now() - t0;
  await execute(
    `UPDATE infra_sources
        SET last_run_ms = $1, last_run_rows = $2, last_error = NULL
      WHERE id = $3`,
    [Date.now(), promoted, SOURCE_ID]
  );

  return { rows: rows.length, promoted, skipped, duration_ms: durationMs };
}

async function recordSourceError(msg) {
  await execute(
    `UPDATE infra_sources
        SET last_run_ms = $1, last_error = $2
      WHERE id = $3`,
    [Date.now(), String(msg).slice(0, 500), SOURCE_ID]
  );
}

/**
 * Tiny CSV parser tailored to URLhaus's quoted-everything format. Avoids
 * pulling in a CSV dependency. Quirks of URLhaus:
 *   - lines starting with `#` are comments
 *   - every field is double-quoted
 *   - commas inside quoted fields are rare but possible (URLs)
 *   - URLhaus does NOT escape internal double-quotes in URLs (their
 *     producer guarantees no `"` in URLs); we tolerate them anyway via
 *     a simple state-machine.
 */
export function parseCsv(text) {
  const lines = text.split(/\r?\n/);
  const rows = [];
  for (const line of lines) {
    if (!line || line.startsWith("#")) continue;
    const fields = [];
    let cur = "";
    let inQuote = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (inQuote) {
        if (c === '"' && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else if (c === '"') {
          inQuote = false;
        } else {
          cur += c;
        }
      } else {
        if (c === '"') inQuote = true;
        else if (c === ",") {
          fields.push(cur);
          cur = "";
        } else cur += c;
      }
    }
    fields.push(cur);
    if (fields.length < 9) continue;
    rows.push({
      id: fields[0],
      date_added: fields[1],
      url: fields[2],
      status: fields[3],
      last_online: fields[4],
      threat: fields[5],
      tags: fields[6],
      urlhaus_link: fields[7],
      reporter: fields[8],
    });
  }
  return rows;
}

/**
 * Build up to 2 observation row-objects for one URLhaus entry: the URL
 * itself + the extracted host (IP or domain). Pure — no DB calls.
 */
function buildObservationRows(r) {
  const tsAdded = parseInt(Date.parse(r.date_added) || 0, 10);
  const tsLastOnline = parseInt(Date.parse(r.last_online) || tsAdded, 10);
  if (!tsAdded) return [];

  const tags = (r.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
  const threat = mapThreat(r.threat);
  const metadata = JSON.stringify({
    status: r.status,
    reporter: r.reporter,
    urlhaus_link: r.urlhaus_link,
    raw_threat: r.threat,
  });

  const out = [
    {
      id: `urlhaus:${r.id}:url`,
      source_id: SOURCE_ID,
      entity_type: "url",
      entity_value: r.url,
      threat_type: threat,
      tags,
      first_seen_ms: tsAdded,
      last_seen_ms: tsLastOnline,
      metadata,
    },
  ];
  const host = extractHost(r.url);
  if (host) {
    out.push({
      id: `urlhaus:${r.id}:host`,
      source_id: SOURCE_ID,
      entity_type: looksLikeIpv4(host) ? "ip" : "domain",
      entity_value: host,
      threat_type: threat,
      tags,
      first_seen_ms: tsAdded,
      last_seen_ms: tsLastOnline,
      metadata,
    });
  }
  return out;
}

/**
 * Multi-row INSERT...ON CONFLICT for a chunk of pre-built rows.
 * Returns the number of rows that were INSERTed or UPDATEd (RETURNING).
 */
async function batchUpsertObs(rowsChunk) {
  if (rowsChunk.length === 0) return 0;
  const cols = 9; // id, source_id, entity_type, entity_value, threat_type, tags, first_seen_ms, last_seen_ms, metadata
  const placeholders = [];
  const params = [];
  rowsChunk.forEach((r, i) => {
    const base = i * cols;
    placeholders.push(
      `($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6}::text[], $${base + 7}, $${base + 8}, $${base + 9}::jsonb)`
    );
    params.push(r.id, r.source_id, r.entity_type, r.entity_value, r.threat_type,
                r.tags, r.first_seen_ms, r.last_seen_ms, r.metadata);
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
  const r = await execute(sql, params);
  return r;
}

// (Per-row upsertObs removed — replaced by batchUpsertObs above.)

function mapThreat(raw) {
  const t = String(raw || "").toLowerCase();
  if (t.includes("malware_download")) return "malware_dl";
  if (t.includes("malware")) return "malware_dl";
  if (t.includes("phish")) return "phishing";
  if (t.includes("c2") || t.includes("c&c")) return "c2";
  return "unknown";
}

function extractHost(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return u.hostname || null;
  } catch {
    return null;
  }
}

const IPV4_RE = /^(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])(?:\.(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])){3}$/;
function looksLikeIpv4(s) {
  return IPV4_RE.test(s);
}
