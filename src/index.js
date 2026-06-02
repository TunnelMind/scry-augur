// scry-augur — entry point.
//
// Periodically pulls public threat-intel feeds and joins them with the
// Familiar-observed actor graph. Sources live in src/sources/; register
// new ones in the SOURCES array below.

import { runUrlhaus } from "./sources/urlhaus.js";
import { runThreatfox } from "./sources/threatfox.js";
import { runTorExit } from "./sources/tor_exit.js";
import { runTorDan } from "./sources/tor_dan.js";
import { runSpamhausDrop } from "./sources/spamhaus_drop.js";
import { runFeodo } from "./sources/feodo.js";
import { runEmergingThreats } from "./sources/emerging_threats.js";
import { runCrtsh } from "./sources/crtsh.js";
import { runMaterializer } from "./materializer.js";
import { shutdown } from "./db.js";

const SOURCE_INTERVAL_MS = parseInt(process.env.SOURCE_INTERVAL_MS, 10) || 30 * 60 * 1000;

const SOURCES = [
  { name: "urlhaus",       run: runUrlhaus },
  { name: "threatfox",     run: runThreatfox },
  { name: "tor_exit",      run: runTorExit },
  { name: "tor_dan",       run: runTorDan },
  { name: "spamhaus_drop", run: runSpamhausDrop },
  { name: "feodo",         run: runFeodo },
  { name: "emerging_threats", run: runEmergingThreats },
  // crtsh runs LAST — it queries domains we just learned about from
  // upstream feeds, so running it after the feeds widens its inputs
  // by one cycle.
  { name: "crtsh",         run: runCrtsh },
];

let running = false;

async function cycle() {
  if (running) {
    console.log("cycle already running, skipping");
    return;
  }
  running = true;
  const t0 = Date.now();
  try {
    for (const s of SOURCES) {
      try {
        const r = await s.run();
        console.log(JSON.stringify({ ts: new Date().toISOString(), source: s.name, ...r }));
      } catch (e) {
        console.error(`source ${s.name} failed:`, e?.message ?? e);
      }
    }
    try {
      const m = await runMaterializer();
      console.log(JSON.stringify({ ts: new Date().toISOString(), materializer: m }));
    } catch (e) {
      console.error("materializer failed:", e?.message ?? e);
    }
    console.log(`cycle complete in ${Date.now() - t0}ms`);
  } finally {
    running = false;
  }
}

async function gracefulShutdown(signal) {
  console.log(`received ${signal}, shutting down`);
  await shutdown();
  process.exit(0);
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

console.log(`scry-augur starting (interval ${SOURCE_INTERVAL_MS}ms)`);
await cycle();
// The interval keeps the event loop alive between cycles. Do NOT call
// .unref() — pg.Pool releases idle TCP sockets after idleTimeoutMillis,
// and without a referenced timer the process exits and the container
// restart-loops. SIGINT/SIGTERM handlers above clear it for clean exit.
setInterval(cycle, SOURCE_INTERVAL_MS);
