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

  // Match actors → infra_observations on IP equality.
  // INSERT ON CONFLICT DO NOTHING means re-runs are idempotent, and
  // matched_at_ms reflects the FIRST time we noticed the link, not the most recent.
  const r = await execute(
    `INSERT INTO actor_infra_links (actor_id, infra_obs_id, matched_at_ms)
     SELECT a.id, o.id, $1
       FROM actors a
       JOIN infra_observations o
         ON o.entity_type = 'ip'
        AND o.entity_value = a.source_ip
     ON CONFLICT (actor_id, infra_obs_id) DO NOTHING`,
    [Date.now()]
  );

  // Defender-tier promotion. (Red-team fix M5.) Flip defender_promoted=1
  // on every infra_observation whose (entity_type, entity_value) is
  // backed by ≥2 distinct source_ids. Defends against single-source
  // poisoning — an attacker who can submit to ONE feed can't promote
  // their false report to authoritative status. Demotion is intentionally
  // NOT done here — once promoted, the row stays promoted. If a source is
  // later compromised, set infra_sources.redistributable=false to stop new
  // promotions but preserve the historical attestation.
  const promoted = await execute(
    `UPDATE infra_observations o
        SET defender_promoted = 1
       FROM (
         SELECT entity_type, entity_value
           FROM infra_observations
          GROUP BY entity_type, entity_value
         HAVING COUNT(DISTINCT source_id) >= 2
       ) AS multi
      WHERE o.entity_type  = multi.entity_type
        AND o.entity_value = multi.entity_value
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
