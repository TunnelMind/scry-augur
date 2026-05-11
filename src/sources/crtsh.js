// crt.sh CT-log search source.
//
// Unlike URLhaus / ThreatFox / Tor exit, crt.sh is NOT a feed of "current
// bad infrastructure" — it's a query interface over Certificate
// Transparency logs. We use it for entity expansion: for each known
// hostile domain in our corpus, look up its CT history and harvest the
// Subject Alternative Names. Same operator → often same cert covering
// multiple "phishing" domains, so the SAN list reveals related infra
// the feed sources don't yet know about.
//
// Endpoint: https://crt.sh/?q=<query>&output=json
// License: public CT data, redistributable.
//
// Strategy (intentionally throttled):
//   - Pick the N most-recent hostile-class domains from infra_observations.
//   - Fetch crt.sh for each (with per-query timeout + try/catch so one
//     bad query doesn't kill the source cycle).
//   - For each cert, split `name_value` on newlines, validate as a
//     domain, and upsert a new infra_observation under source `crtsh`.
//   - Re-querying on later cycles is cheap (upsert), so no state table.

import { execute, query } from "../db.js";
import { fetchWithCertInfo, checkAndRecordCertFingerprint } from "../lib/cert-fetch.js";

const SOURCE_ID = "crtsh";
// crt.sh's Postgres-backed search is slow (~20s for successful queries),
// and its CF-fronted CDN aggressively 502s when it sees burst traffic.
// Tunings (verified empirically against the live endpoint from the VPS):
//   - PER_QUERY_TIMEOUT_MS: must be >20s or we abort real wins. 45s headroom.
//   - INTER_QUERY_DELAY_MS: ~4s between queries to dodge the burst detector.
//   - PER_CYCLE_QUERIES: lower count beats more retries — 3 is the sweet spot.
//   - RETRY_BACKOFF_MS: a single retry on 5xx with a 10s back-off catches
//     the common transient 502.
const PER_CYCLE_QUERIES = parseInt(process.env.CRTSH_PER_CYCLE, 10) || 3;
const PER_QUERY_TIMEOUT_MS = parseInt(process.env.CRTSH_TIMEOUT_MS, 10) || 45_000;
const INTER_QUERY_DELAY_MS = parseInt(process.env.CRTSH_DELAY_MS, 10) || 4_000;
const RETRY_BACKOFF_MS = parseInt(process.env.CRTSH_RETRY_MS, 10) || 10_000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function runCrtsh() {
  const t0 = Date.now();
  const ua = process.env.AUGUR_UA || "scry-augur/0.1";

  // Pick the N most-recent hostile-class domains we have. RANDOM tie-break
  // would spread coverage; LAST_SEEN orders by what's freshly active.
  const targets = await query(
    `SELECT entity_value
       FROM infra_observations
      WHERE entity_type = 'domain'
        AND threat_type IN ('malware_dl','phishing','c2')
      ORDER BY last_seen_ms DESC
      LIMIT $1`,
    [PER_CYCLE_QUERIES]
  );

  if (targets.length === 0) {
    await execute(
      `UPDATE infra_sources
          SET last_run_ms = $1, last_run_rows = 0, last_error = NULL
        WHERE id = $2`,
      [Date.now(), SOURCE_ID]
    );
    return { rows: 0, promoted: 0, skipped: 0, duration_ms: Date.now() - t0 };
  }

  let totalCerts = 0;
  let promoted = 0;
  let queriesSucceeded = 0;
  let retriesUsed = 0;
  const allRows = [];

  for (let i = 0; i < targets.length; i++) {
    const target = targets[i].entity_value;
    // Querying the bare hostname (`ftscfs.logicstack.ink`) only matches
    // certs whose name fields contain that exact string — usually zero.
    // The operator-graph value is in the wildcard form: querying
    // `%.logicstack.ink` returns ALL certs covering any subdomain of
    // logicstack.ink, surfacing siblings the feed sources don't yet
    // know about.
    const queryStr = wildcardForm(target);
    const result = await queryWithRetry(queryStr, ua);
    if (result.retried) retriesUsed++;
    if (result.ok) {
      queriesSucceeded++;
      totalCerts += result.certs.length;
      for (const cert of result.certs) {
        for (const obs of buildObservationRowsFromCert(target, queryStr, cert)) {
          allRows.push(obs);
        }
      }
    } else {
      console.warn(JSON.stringify({
        source: SOURCE_ID,
        event: "query_failed",
        target,
        query: queryStr,
        message: result.message,
      }));
    }
    // Inter-query pacing — only between queries, not after the last one.
    if (i < targets.length - 1 && INTER_QUERY_DELAY_MS > 0) {
      await sleep(INTER_QUERY_DELAY_MS);
    }
  }

  const BATCH = 500;
  for (let i = 0; i < allRows.length; i += BATCH) {
    promoted += await batchUpsertObs(allRows.slice(i, i + BATCH));
  }

  await execute(
    `UPDATE infra_sources
        SET last_run_ms = $1, last_run_rows = $2, last_error = NULL
      WHERE id = $3`,
    [Date.now(), promoted, SOURCE_ID]
  );

  return {
    rows: totalCerts,
    promoted,
    skipped: allRows.length - promoted,
    queries: targets.length,
    queries_ok: queriesSucceeded,
    retries_used: retriesUsed,
    duration_ms: Date.now() - t0,
  };
}

/**
 * Single-shot fetch wrapped in a 5xx-retry. Returns
 * `{ ok, certs?, message?, retried }`. Never throws.
 */
async function queryWithRetry(queryStr, ua) {
  let lastMessage = null;
  let didRetry = false;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const certs = await fetchCrtshOnce(queryStr, ua);
      return { ok: true, certs, retried: didRetry };
    } catch (e) {
      lastMessage = e?.message ?? String(e);
      // Retry once on transient 5xx; bail immediately on 4xx, JSON errors,
      // or timeouts (those won't get better by waiting).
      if (attempt === 0 && /^HTTP 5\d\d/.test(lastMessage)) {
        didRetry = true;
        await sleep(RETRY_BACKOFF_MS);
        continue;
      }
      break;
    }
  }
  return { ok: false, message: lastMessage, retried: didRetry };
}

async function fetchCrtshOnce(domain, ua) {
  const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
  // crt.sh's CDN rejects (502/000) plain "scry-augur/X.Y (https://…)"
  // UAs as bot-shaped. A Mozilla-compatible UA still identifies us but
  // gets past the naive filter. Verified 2026-05-10: the same query
  // returns clean JSON with this UA and gets 502 with the augur UA.
  const compatUa = `Mozilla/5.0 (compatible; ${ua})`;
  const fetchPromise = fetchWithCertInfo(url, {
    headers: { "User-Agent": compatUa, Accept: "application/json" },
  });
  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("timeout")), PER_QUERY_TIMEOUT_MS)
  );
  const resp = await Promise.race([fetchPromise, timeoutPromise]);

  // SPKI tracking is best-effort here — record on first successful query
  // of each cycle. Subsequent same-cycle queries reuse the same cert.
  await checkAndRecordCertFingerprint(SOURCE_ID, resp);

  if (resp.status !== 200) {
    throw new Error(`HTTP ${resp.status}`);
  }
  // crt.sh returns a JSON array, sometimes empty, occasionally `[]\n`.
  const trimmed = resp.body.trim();
  if (!trimmed || trimmed === "[]") return [];
  try {
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    throw new Error(`invalid JSON (${trimmed.length} bytes)`);
  }
}

const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

/**
 * Parse one cert record into 0+ observation rows. Each unique SAN
 * domain yields one row, keyed by `crtsh:<cert_id>:<domain>` so the
 * same cert covering N names produces N rows.
 *
 * Skips the seed target itself (we already know it) and any wildcard
 * SANs (e.g. `*.logicstack.ink` — already implied by the query).
 */
export function buildObservationRowsFromCert(seedTarget, queryStr, cert) {
  if (!cert || !cert.id || !cert.name_value) return [];
  const tsFirst = parseCrtshTime(cert.entry_timestamp || cert.not_before);
  const tsLast = parseCrtshTime(cert.not_after) || tsFirst;
  if (!tsFirst) return [];

  const names = String(cert.name_value)
    .split(/\r?\n/)
    .map((n) => n.trim().toLowerCase())
    .filter((n) => n && !n.startsWith("*.") && DOMAIN_RE.test(n));

  const seedLower = seedTarget.toLowerCase();
  const fresh = names.filter((n) => n !== seedLower);

  const seen = new Set();
  const out = [];
  for (const name of fresh) {
    if (seen.has(name)) continue;
    seen.add(name);
    out.push({
      id: `crtsh:${cert.id}:${name}`,
      source_id: SOURCE_ID,
      entity_type: "domain",
      entity_value: name,
      // crt.sh itself doesn't assert maliciousness — it just shows the
      // cert exists. Tagged `unknown` so it never promotes alone; it
      // can corroborate when a feed source independently flags the
      // same name.
      threat_type: "unknown",
      tags: ["crtsh", `via:${seedTarget}`],
      first_seen_ms: tsFirst,
      last_seen_ms: tsLast,
      metadata: JSON.stringify({
        cert_id: cert.id,
        issuer_name: cert.issuer_name,
        common_name: cert.common_name,
        not_before: cert.not_before,
        not_after: cert.not_after,
        seed_query: seedTarget,
        crt_sh_query: queryStr,
      }),
    });
  }
  return out;
}

/**
 * Convert a hostile target into a crt.sh wildcard query that captures
 * sibling SANs from the same operator. For most TLDs we strip to the
 * last 2 labels and prefix `%.`. Bail to the bare target for short
 * names (already at the apex) or names with a "complex" public suffix
 * we'd over-match against (`co.uk`, `com.cn`, `co.jp`, etc.).
 *
 * Public suffix list would be more correct but a tiny denylist covers
 * 99% of risk and keeps the deps minimal.
 */
const COMPLEX_SUFFIXES = new Set([
  "co.uk","co.jp","co.kr","co.in","co.za","co.nz","co.il","com.au","com.br",
  "com.cn","com.tr","com.mx","com.ar","com.tw","com.hk","com.sg","com.vn",
  "com.pl","com.ua","com.ru","ne.jp","or.jp","ac.jp","ac.uk","gov.uk","org.uk",
]);

export function wildcardForm(target) {
  if (typeof target !== "string") return target;
  const labels = target.toLowerCase().split(".").filter(Boolean);
  if (labels.length < 3) return target;
  const last2 = labels.slice(-2).join(".");
  if (COMPLEX_SUFFIXES.has(last2)) return target;
  return `%.${last2}`;
}

function parseCrtshTime(raw) {
  if (!raw || typeof raw !== "string") return 0;
  // crt.sh emits ISO-ish "2026-05-08T07:59:58" — append Z if no zone.
  const normalized = /[Zz]|[+-]\d{2}:?\d{2}$/.test(raw) ? raw : raw + "Z";
  const ts = Date.parse(normalized);
  return Number.isFinite(ts) ? ts : 0;
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
