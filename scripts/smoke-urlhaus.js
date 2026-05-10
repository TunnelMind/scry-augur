// One-shot smoke for the URLhaus source. Doesn't apply schema; assumes
// tables exist. Pulls one CSV cycle, runs the materializer, prints
// summary stats.

import { runUrlhaus } from "../src/sources/urlhaus.js";
import { runMaterializer } from "../src/materializer.js";
import { query, shutdown } from "../src/db.js";

console.log("connecting:", process.env.PG_URL?.replace(/:[^:@]+@/, ":***@"));

try {
  console.log("\n=== URLhaus run ===");
  const r = await runUrlhaus();
  console.log("  result:", r);

  console.log("\n=== materializer ===");
  const m = await runMaterializer();
  console.log("  result:", m);

  console.log("\n=== current corpus snapshot ===");
  const counts = await query(`
    SELECT
      (SELECT COUNT(*) FROM infra_sources)         AS sources,
      (SELECT COUNT(*) FROM infra_observations)    AS observations,
      (SELECT COUNT(DISTINCT entity_value) FROM infra_observations WHERE entity_type='ip') AS distinct_ips,
      (SELECT COUNT(DISTINCT entity_value) FROM infra_observations WHERE entity_type='domain') AS distinct_domains,
      (SELECT COUNT(DISTINCT entity_value) FROM infra_observations WHERE entity_type='url') AS distinct_urls,
      (SELECT COUNT(*) FROM actor_infra_links)     AS actor_links
  `);
  console.log(counts[0]);

  console.log("\n=== top threat types in last 24h ===");
  const top = await query(`
    SELECT threat_type, COUNT(*) AS n
      FROM infra_observations
     WHERE last_seen_ms >= $1
     GROUP BY threat_type
     ORDER BY n DESC`, [Date.now() - 86400000]);
  for (const r of top) console.log(`  ${r.threat_type ?? '(null)'}  ${r.n}`);

  console.log("\nsmoke ok");
} catch (e) {
  console.error("smoke FAIL:", e);
  process.exitCode = 1;
} finally {
  await shutdown();
}
