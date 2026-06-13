// ThreatFox (abuse.ch) source.
//
// abuse.ch's POST API at /api/v1/ requires an Auth-Key (since 2025-01-01).
// The static bulk dump at /export/json/recent/ remains anonymous (it's
// the same dataset, snapshotted hourly). We use the bulk dump.
//
// Endpoint: https://threatfox.abuse.ch/export/json/recent/
// License: CC0. Redistributable.
//
// Format (id-keyed map; each value is an array — usually length 1):
//   {
//     "1808227": [{
//       "ioc_value": "1.2.3.4:443" | "evil.com" | "https://…" | "<sha256>",
//       "ioc_type":  "ip:port" | "domain" | "url" | "sha256_hash" | …,
//       "threat_type": "payload" | "botnet_cc" | …,
//       "malware_printable": "Cobalt Strike",
//       "first_seen_utc": "2026-05-08 07:59:58",
//       "last_seen_utc":  "2026-05-09 12:00:00" | null,
//       "confidence_level": 90,
//       "tags": "comma,separated,string",
//       "reporter": "anonymous",
//       "reference": "…"
//     }]
//   }
//
// Cert hygiene (red-team round-2 AI-X2) lives in lib/cert-fetch.js.

import { execute } from "../db.js";
import { fetchWithCertInfo, checkAndRecordCertFingerprint } from "../lib/cert-fetch.js";
import { isV6 } from "../lib/ipv6.js";

const BULK_URL = "https://threatfox.abuse.ch/export/json/recent/";
const SOURCE_ID = "threatfox";

export async function runThreatfox() {
  const t0 = Date.now();
  const ua = process.env.AUGUR_UA || "scry-augur/0.1";

  let respBody;
  let respStatus;
  try {
    const resp = await fetchWithCertInfo(BULK_URL, {
      headers: { "User-Agent": ua, Accept: "application/json" },
    });
    respStatus = resp.status;
    respBody = resp.body;
    await checkAndRecordCertFingerprint(SOURCE_ID, resp);
    if (resp.status !== 200) {
      throw new Error(`threatfox HTTP ${resp.status}: ${truncate(resp.body, 200)}`);
    }
  } catch (e) {
    await recordSourceError(`fetch failed: ${e.message}`);
    throw e;
  }

  let parsed;
  try {
    parsed = JSON.parse(respBody);
  } catch (e) {
    await recordSourceError(`invalid JSON: ${e.message}`);
    throw new Error(`threatfox returned non-JSON (status ${respStatus})`);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    await recordSourceError("unexpected top-level shape");
    throw new Error("threatfox bulk dump did not return an object");
  }

  const allRows = [];
  let totalIocs = 0;
  for (const [id, variants] of Object.entries(parsed)) {
    if (!Array.isArray(variants)) continue;
    for (const v of variants) {
      totalIocs++;
      const obs = buildObservationRow(id, v);
      if (obs) allRows.push(obs);
    }
  }

  let promoted = 0;
  const BATCH = 500;
  for (let i = 0; i < allRows.length; i += BATCH) {
    promoted += await batchUpsertObs(allRows.slice(i, i + BATCH));
  }
  const skipped = totalIocs - promoted;

  await execute(
    `UPDATE infra_sources
        SET last_run_ms = $1, last_run_rows = $2, last_error = NULL
      WHERE id = $3`,
    [Date.now(), promoted, SOURCE_ID]
  );

  return { rows: totalIocs, promoted, skipped, duration_ms: Date.now() - t0 };
}

async function recordSourceError(msg) {
  await execute(
    `UPDATE infra_sources
        SET last_run_ms = $1, last_error = $2
      WHERE id = $3`,
    [Date.now(), String(msg).slice(0, 500), SOURCE_ID]
  );
}

function truncate(s, n) {
  if (typeof s !== "string") return "";
  return s.length > n ? s.slice(0, n) + "…" : s;
}

/**
 * Map a single ThreatFox bulk-dump row to one infra_observations row,
 * or null if the IOC type isn't representable in our schema (md5/sha1
 * hashes aren't — schema CHECK only allows sha256). Pure — no DB calls.
 */
export function buildObservationRow(id, r) {
  if (!r || !r.ioc_value || !id) return null;

  const tsFirst = parseTfTime(r.first_seen_utc);
  const tsLast = parseTfTime(r.last_seen_utc) || tsFirst;
  if (!tsFirst) return null;

  const mapping = mapIoc(r.ioc_type, r.ioc_value);
  if (!mapping) return null;

  const tags =
    typeof r.tags === "string"
      ? r.tags.split(",").map((t) => t.trim()).filter(Boolean)
      : Array.isArray(r.tags)
      ? r.tags.filter(Boolean)
      : [];
  const threat = mapThreat(r.threat_type);

  const metadata = JSON.stringify({
    threat_type_raw: r.threat_type,
    ioc_type_raw: r.ioc_type,
    malware: r.malware_printable || r.malware,
    malware_alias: r.malware_alias,
    confidence_level: r.confidence_level,
    is_compromised: r.is_compromised,
    reference: r.reference,
    reporter: r.reporter,
    port: mapping.port ?? undefined,
  });

  return {
    id: `threatfox:${id}`,
    source_id: SOURCE_ID,
    entity_type: mapping.entity_type,
    entity_value: mapping.entity_value,
    threat_type: threat,
    tags,
    first_seen_ms: tsFirst,
    last_seen_ms: tsLast,
    metadata,
  };
}

/**
 * ThreatFox bulk-dump timestamps are naive UTC, e.g. "2026-05-08 07:59:58"
 * (no timezone marker). Treat them as UTC.
 */
function parseTfTime(raw) {
  if (!raw || typeof raw !== "string") return 0;
  const normalized = raw.includes("T") ? raw : raw.replace(" ", "T") + "Z";
  const ts = Date.parse(normalized);
  return Number.isFinite(ts) ? ts : 0;
}

function mapThreat(raw) {
  const t = String(raw || "").toLowerCase();
  if (t.includes("botnet_cc") || t === "c2" || t.includes("c&c")) return "c2";
  if (t.includes("payload")) return "malware_dl";
  if (t.includes("phish")) return "phishing";
  return "unknown";
}

const IPV4_RE = /^(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])(?:\.(?:0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])){3}$/;
const SHA256_RE = /^[a-f0-9]{64}$/i;

/**
 * Map ThreatFox ioc_type + ioc value to (entity_type, entity_value, [port]).
 * Returns null for unrepresentable types (md5/sha1 hashes — schema only
 * accepts sha256).
 */
export function mapIoc(iocType, iocValue) {
  if (!iocType || !iocValue) return null;
  switch (String(iocType).toLowerCase()) {
    case "ip:port": {
      // v4: "1.2.3.4:443". v6: "[2001:db8::1]:443" (bracketed) or a bare v6
      // literal (every hextet has a colon, so lastIndexOf would mis-split).
      const v = String(iocValue).trim();
      let ip, port = null;
      if (v.startsWith("[")) {
        const end = v.indexOf("]");
        if (end === -1) return null;
        ip = v.slice(1, end);
        const rest = v.slice(end + 1);
        if (rest.startsWith(":")) port = Number(rest.slice(1));
      } else if (isV6(v)) {
        ip = v; // bare v6, no port
      } else {
        const idx = v.lastIndexOf(":");
        ip = idx > -1 ? v.slice(0, idx) : v;
        port = idx > -1 ? Number(v.slice(idx + 1)) : null;
      }
      if (!IPV4_RE.test(ip) && !isV6(ip)) return null;
      return { entity_type: "ip", entity_value: ip, port: Number.isFinite(port) ? port : null };
    }
    case "domain": {
      return { entity_type: "domain", entity_value: iocValue };
    }
    case "url": {
      return { entity_type: "url", entity_value: iocValue };
    }
    case "sha256_hash": {
      if (!SHA256_RE.test(iocValue)) return null;
      return { entity_type: "sha256", entity_value: iocValue.toLowerCase() };
    }
    // md5_hash, sha1_hash — not representable in current schema; skip.
    default:
      return null;
  }
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
