// One-shot smoke for the Tor exit source.

import { runTorExit } from "../src/sources/tor_exit.js";
import { runMaterializer } from "../src/materializer.js";
import { query, shutdown } from "../src/db.js";

console.log("connecting:", process.env.PG_URL?.replace(/:[^:@]+@/, ":***@"));

try {
  console.log("\n=== Tor exit run ===");
  const r = await runTorExit();
  console.log("  result:", r);

  console.log("\n=== materializer ===");
  const m = await runMaterializer();
  console.log("  result:", m);

  console.log("\n=== current corpus snapshot ===");
  const counts = await query(`
    SELECT
      (SELECT COUNT(*) FROM infra_sources)         AS sources,
      (SELECT COUNT(*) FROM infra_observations)    AS observations,
      (SELECT COUNT(*) FROM infra_observations WHERE source_id='tor_exit')  AS tor_obs,
      (SELECT COUNT(*) FROM infra_observations WHERE source_id='threatfox') AS threatfox_obs,
      (SELECT COUNT(*) FROM infra_observations WHERE source_id='urlhaus')   AS urlhaus_obs,
      (SELECT COUNT(*) FROM actor_infra_links)     AS actor_links,
      (SELECT COUNT(*) FROM infra_observations WHERE defender_promoted = 1) AS promoted_obs
  `);
  console.log(counts[0]);

  console.log("\n=== Familiar actors that ARE tor exits ===");
  const torActors = await query(`
    SELECT a.id, a.source_ip
      FROM actors a
      JOIN infra_observations o
        ON o.entity_type = 'ip'
       AND o.entity_value = a.source_ip
       AND o.source_id = 'tor_exit'
     LIMIT 10`);
  if (torActors.length === 0) {
    console.log("  (none — no fleet observation has come from a tor exit IP)");
  } else {
    for (const r of torActors) console.log(`  ${r.id}  ${r.source_ip}`);
  }

  console.log("\nsmoke ok");
} catch (e) {
  console.error("smoke FAIL:", e?.message ?? e);
  process.exitCode = 1;
} finally {
  await shutdown();
}
