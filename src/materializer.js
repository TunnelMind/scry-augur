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

  const totalLinks = await query(`SELECT COUNT(*)::int AS c FROM actor_infra_links`);
  const linkedActors = await query(
    `SELECT COUNT(DISTINCT actor_id)::int AS c FROM actor_infra_links`
  );

  return {
    new_links: r,
    total_links: totalLinks[0].c,
    actors_with_links: linkedActors[0].c,
    duration_ms: Date.now() - t0,
  };
}
