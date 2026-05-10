// One-shot smoke for the ThreatFox source. Mirrors smoke-urlhaus.
// Assumes schema/001_init.sql has been applied. If THREATFOX_AUTH_KEY is
// not set the API will reject with HTTP 401/403 — surface that clearly.

import { runThreatfox } from "../src/sources/threatfox.js";
import { runMaterializer } from "../src/materializer.js";
import { query, shutdown } from "../src/db.js";

console.log("connecting:", process.env.PG_URL?.replace(/:[^:@]+@/, ":***@"));
console.log("auth-key set:", Boolean(process.env.THREATFOX_AUTH_KEY));

try {
  console.log("\n=== ThreatFox run ===");
  const r = await runThreatfox();
  console.log("  result:", r);

  console.log("\n=== materializer ===");
  const m = await runMaterializer();
  console.log("  result:", m);

  console.log("\n=== current corpus snapshot ===");
  const counts = await query(`
    SELECT
      (SELECT COUNT(*) FROM infra_sources)         AS sources,
      (SELECT COUNT(*) FROM infra_observations)    AS observations,
      (SELECT COUNT(*) FROM infra_observations WHERE source_id='threatfox') AS threatfox_obs,
      (SELECT COUNT(*) FROM infra_observations WHERE source_id='urlhaus')   AS urlhaus_obs,
      (SELECT COUNT(DISTINCT entity_value) FROM infra_observations WHERE entity_type='ip') AS distinct_ips,
      (SELECT COUNT(*) FROM actor_infra_links)     AS actor_links,
      (SELECT COUNT(*) FROM infra_observations WHERE defender_promoted = 1) AS promoted_obs
  `);
  console.log(counts[0]);

  console.log("\n=== ThreatFox threat_type breakdown ===");
  const top = await query(`
    SELECT threat_type, COUNT(*) AS n
      FROM infra_observations
     WHERE source_id = 'threatfox'
     GROUP BY threat_type
     ORDER BY n DESC`);
  for (const r of top) console.log(`  ${r.threat_type ?? '(null)'}  ${r.n}`);

  console.log("\n=== cross-source IPs (URLhaus ∩ ThreatFox) — top 10 ===");
  const overlap = await query(`
    SELECT entity_value,
           array_agg(DISTINCT source_id ORDER BY source_id) AS sources,
           array_agg(DISTINCT threat_type) AS threats
      FROM infra_observations
     WHERE entity_type='ip'
     GROUP BY entity_value
    HAVING COUNT(DISTINCT source_id) >= 2
     ORDER BY entity_value
     LIMIT 10`);
  for (const r of overlap) {
    console.log(`  ${r.entity_value}  sources=${JSON.stringify(r.sources)}  threats=${JSON.stringify(r.threats)}`);
  }
  if (overlap.length === 0) console.log("  (no cross-source overlap yet)");

  console.log("\nsmoke ok");
} catch (e) {
  console.error("smoke FAIL:", e?.message ?? e);
  process.exitCode = 1;
} finally {
  await shutdown();
}
