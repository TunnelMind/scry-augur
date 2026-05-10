// Postgres connection pool. Same shape as scry-server/src/db.js — Augur
// writes to the same `scry` database and joins with scry-server's `actors`
// table for the materializer.

import pg from "pg";

const pool = new pg.Pool({
  connectionString: process.env.PG_URL,
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

pool.on("error", (e) => console.error("pg pool error:", e));

export async function query(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows;
}

export async function queryOne(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows[0] ?? null;
}

export async function execute(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rowCount;
}

export async function shutdown() {
  await pool.end();
}
