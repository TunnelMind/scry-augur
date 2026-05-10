// Shared HTTPS fetch helper that records the peer cert's
// SubjectPublicKeyInfo SHA256 alongside the response. Sources call
// `fetchWithCertInfo()` to get both, then `checkAndRecordCertFingerprint()`
// to compare against the previously-seen value and warn on change.
//
// SECURITY (red-team round-2 AI-X2): we don't pin the cert (operational
// pain on rotation outweighs the marginal threat at this scale), but we
// DO log the SPKI SHA256 each fetch and WARN if it changes. SPKI hashes
// are stable across cert renewals as long as the key stays the same —
// change implies key rotation OR MITM. Operator can investigate.
//
// Why this lives here: extracted from urlhaus.js + threatfox.js once we
// hit a third source (tor_exit). Same code, three call sites — single
// source of truth.

import { request as httpsRequest } from "node:https";
import { createHash } from "node:crypto";
import { execute, queryOne } from "../db.js";

/**
 * GET an HTTPS URL and resolve with both the response body and the peer
 * cert's SPKI fingerprint. Standard TLS validation (default) is in
 * force; the SPKI is for change-detection logging, NOT for pinning.
 *
 * Captures cert info at response start, before any body bytes are read,
 * because `res.socket` may be released back to the agent pool by the
 * time 'end' fires for small responses.
 */
export function fetchWithCertInfo(url, { method = "GET", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      url,
      {
        method,
        headers: body
          ? { "Content-Length": Buffer.byteLength(body), ...headers }
          : headers,
      },
      (res) => {
        const cert = res.socket?.getPeerCertificate?.(true) ?? null;
        const spkiSha256 = cert?.pubkey
          ? createHash("sha256").update(cert.pubkey).digest("base64")
          : null;
        const issuer = cert?.issuer?.O || cert?.issuer?.CN || null;
        const subject = cert?.subject?.CN || null;
        const validTo = cert?.valid_to || null;
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            body: Buffer.concat(chunks).toString("utf8"),
            spki_sha256: spkiSha256,
            issuer,
            subject,
            valid_to: validTo,
          });
        });
      }
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

/**
 * Compare the just-observed SPKI against the previously-stored value
 * for this source and emit a structured warning on change. Always
 * updates `last_seen_spki_sha256` and `last_seen_spki_at_ms` so the
 * baseline tracks the most recent observation.
 *
 * Does NOT abort on change — false positives during legitimate rotation
 * would silence the source entirely. Operator confirms via the log.
 */
export async function checkAndRecordCertFingerprint(sourceId, current) {
  const { spki_sha256: spki, issuer, subject, valid_to: validTo } = current;
  if (!spki) return;

  const prev = await queryOne(
    `SELECT last_seen_spki_sha256 FROM infra_sources WHERE id = $1`,
    [sourceId]
  );
  const prevSpki = prev?.last_seen_spki_sha256 || null;
  if (prevSpki && prevSpki !== spki) {
    console.warn(JSON.stringify({
      source: sourceId,
      event: "cert_spki_changed",
      severity: "warning",
      previous_spki: prevSpki,
      current_spki: spki,
      issuer, subject, valid_to: validTo,
      hint: "verify legitimate cert rotation vs MITM before continuing trust",
    }));
  }
  await execute(
    `UPDATE infra_sources
        SET last_seen_spki_sha256 = $1, last_seen_spki_at_ms = $2
      WHERE id = $3`,
    [spki, Date.now(), sourceId]
  );
}
