// scry-augur — entry point.
//
// Periodically pulls public threat-intel feeds and joins them with the
// Familiar-observed actor graph. Currently a single-source POC (URLhaus);
// add new sources under src/sources/ and register them below.

import { runUrlhaus } from "./sources/urlhaus.js";
import { runThreatfox } from "./sources/threatfox.js";
import { runTorExit } from "./sources/tor_exit.js";
import { runMaterializer } from "./materializer.js";
import { shutdown } from "./db.js";

const SOURCE_INTERVAL_MS = parseInt(process.env.SOURCE_INTERVAL_MS, 10) || 30 * 60 * 1000;

const SOURCES = [
  { name: "urlhaus", run: runUrlhaus },
  { name: "threatfox", run: runThreatfox },
  { name: "tor_exit", run: runTorExit },
  // Add more here as they're implemented.
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
setInterval(cycle, SOURCE_INTERVAL_MS).unref();
// Keep alive until SIGTERM
setInterval(() => {}, 1 << 30).unref();
