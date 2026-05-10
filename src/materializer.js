// Augur materializer — joins Familiar-observed actors with Augur-imported
// infrastructure observations.
//
// Runs after the source pulls (every 30 min). For each actor whose
// source_ip appears in infra_observations as entity_type='ip', insert a
// link row. INSERT ON CONFLICT DO NOTHING for idempotency.
//
// Domain/URL matching is harder (would need DNS resolution to map domain→ip,
// which would re-fetch attacker infrastructure → out of scope per design
// rules). Defer to a passive-DNS source as a future enhancement.

import { execute, query } from "./db.js";

export async function runMaterializer() {
  const t0 = Date.now();

  // Match actors → infra_observations on IP equality OR CIDR containment.
  // INSERT ON CONFLICT DO NOTHING means re-runs are idempotent, and
  // matched_at_ms reflects the FIRST time we noticed the link.
  //
  // Two pathways:
  //   1. Exact-IP match (URLhaus, ThreatFox, Tor exit) — fast equality
  //      join, indexed by idx_infra_obs_entity.
  //   2. CIDR containment (Spamhaus DROP / EDROP) — `<<=` operator on
  //      inet-cast values. No covering index, but the CIDR list is
  //      small (~hundreds of entries) so the scan is cheap.
  const r = await execute(
    `INSERT INTO actor_infra_links (actor_id, infra_obs_id, matched_at_ms)
     SELECT a.id, o.id, $1
       FROM actors a
       JOIN infra_observations o
         ON (o.entity_type = 'ip'   AND o.entity_value = a.source_ip)
         OR (o.entity_type = 'cidr' AND a.source_ip::inet <<= o.entity_value::inet)
     ON CONFLICT (actor_id, infra_obs_id) DO NOTHING`,
    [Date.now()]
  );

  // Defender-tier promotion. (Red-team fix M5 + AI-X1 round-2.)
  //
  // Original M5 rule: ≥2 distinct sources on the same (entity_type,
  // entity_value) → promote. That was too permissive — Tor exit list
  // saying tor_exit + URLhaus saying malware_dl on the same IP would
  // both count as "agreement" even though they're asserting different
  // facts about the same entity.
  //
  // Round-2 tightening: ≥2 distinct sources MUST agree on the same
  // threat_class. Classes:
  //   hostile        — { malware_dl, phishing, c2 }
  //   tor_exit       — { tor_exit }
  //   scanner        — { scanner }
  //   netblock       — { netblock_blocked } (Spamhaus DROP etc)
  //   unknown        — anything else; never promotes
  //
  // Tor + URLhaus on the same IP → different classes → no promotion.
  // URLhaus(malware_dl) + ThreatFox(c2) on the same IP → both 'hostile'
  // → promotion fires. That's the corroboration we want.
  //
  // Demotion is intentionally NOT done here — once promoted, the row stays
  // promoted. If a source is later compromised, set
  // infra_sources.redistributable=false to stop new promotions but preserve
  // the historical attestation.
  const promoted = await execute(
    `WITH classed AS (
       SELECT id, source_id, entity_type, entity_value,
              CASE
                WHEN threat_type IN ('malware_dl','phishing','c2')           THEN 'hostile'
                WHEN threat_type = 'tor_exit'                                THEN 'tor_exit'
                WHEN threat_type = 'scanner'                                 THEN 'scanner'
                WHEN threat_type IN ('netblock_blocked','spam','blocklisted') THEN 'netblock'
                ELSE 'unknown'
              END AS threat_class
         FROM infra_observations
     ),
     promotable AS (
       SELECT entity_type, entity_value, threat_class
         FROM classed
        WHERE threat_class <> 'unknown'
        GROUP BY entity_type, entity_value, threat_class
       HAVING COUNT(DISTINCT source_id) >= 2
     )
     UPDATE infra_observations o
        SET defender_promoted = 1
       FROM promotable p, classed c
      WHERE c.id = o.id
        AND c.entity_type  = p.entity_type
        AND c.entity_value = p.entity_value
        AND c.threat_class = p.threat_class
        AND o.defender_promoted = 0`
  );

  const totalLinks = await query(`SELECT COUNT(*)::int AS c FROM actor_infra_links`);
  const linkedActors = await query(
    `SELECT COUNT(DISTINCT actor_id)::int AS c FROM actor_infra_links`
  );
  const promotedTotal = await query(
    `SELECT COUNT(*)::int AS c FROM infra_observations WHERE defender_promoted = 1`
  );

  return {
    new_links: r,
    total_links: totalLinks[0].c,
    actors_with_links: linkedActors[0].c,
    newly_promoted: promoted,
    total_promoted: promotedTotal[0].c,
    duration_ms: Date.now() - t0,
  };
}
