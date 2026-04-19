#!/usr/bin/env node
// Poolsmith stress tester — simulates N concurrent clients against a DSN.
//
// Usage:
//   DSN="postgres://user:pw@host:6432/db" node stress-test.js
//   DSN="..." CONCURRENCY=300 DURATION_SEC=30 QUERY="SELECT 1" node stress-test.js
//
// Each simulated client opens ONE real TCP connection (no pool), loops running
// the query until the duration elapses, and records latency samples.  At the
// end we print total throughput, p50/p95/p99/max, and error counts.

import pg from 'pg';
import process from 'node:process';

const DSN         = process.env.DSN         || 'postgres://postgres@localhost:6432/postgres';
const CONCURRENCY = parseInt(process.env.CONCURRENCY || '300', 10);
const DURATION_MS = parseInt(process.env.DURATION_SEC || '15', 10) * 1000;
const QUERY       = process.env.QUERY       || 'SELECT 1';
const RAMP_MS     = parseInt(process.env.RAMP_MS     || '500', 10);
const REPORT_MS   = parseInt(process.env.REPORT_SEC  || '5', 10) * 1000;
const KEEPALIVE   = (process.env.KEEPALIVE || '1') === '1';

// Per-client state — avoids lock contention, just a struct.
const stats = {
  started:      0,
  connected:    0,
  connErrors:   0,
  queries:      0,
  queryErrors:  0,
  latencies:    [],    // grows without bound — see note
  startedAt:    0,
  finishedAt:   0,
  perClient:    new Array(CONCURRENCY).fill(0),
};

// Keeping every latency sample is wasteful; keep a reservoir instead.
const RESERVOIR_CAP = 200_000;
function record(ns) {
  if (stats.latencies.length < RESERVOIR_CAP) {
    stats.latencies.push(ns);
    return;
  }
  const j = Math.floor(Math.random() * stats.queries);
  if (j < RESERVOIR_CAP) stats.latencies[j] = ns;
}

function quantile(sorted, q) {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * q));
  return sorted[idx];
}
function fmtNs(ns) {
  if (ns < 1_000) return `${ns.toFixed(0)} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(1)} µs`;
  if (ns < 1_000_000_000) return `${(ns / 1_000_000).toFixed(2)} ms`;
  return `${(ns / 1_000_000_000).toFixed(2)} s`;
}

async function runClient(id, deadline) {
  const client = new pg.Client({
    connectionString: DSN,
    keepAlive: KEEPALIVE,
    keepAliveInitialDelayMillis: 10_000,
  });
  stats.started++;
  try {
    await client.connect();
  } catch (e) {
    stats.connErrors++;
    return;
  }
  stats.connected++;

  try {
    while (Date.now() < deadline) {
      const t0 = process.hrtime.bigint();
      try {
        await client.query(QUERY);
        const ns = Number(process.hrtime.bigint() - t0);
        stats.queries++;
        stats.perClient[id]++;
        record(ns);
      } catch (e) {
        stats.queryErrors++;
        // If the connection itself died, bail so we don't spin on errors.
        if (/connection/.test(String(e?.message)) || e?.code === 'ECONNRESET') return;
      }
    }
  } finally {
    try { await client.end(); } catch {}
  }
}

async function periodicReport() {
  const t0 = Date.now();
  while (Date.now() - t0 < DURATION_MS + RAMP_MS) {
    await new Promise(r => setTimeout(r, REPORT_MS));
    const elapsed = (Date.now() - stats.startedAt) / 1000;
    if (elapsed <= 0) continue;
    const rps = stats.queries / elapsed;
    console.log(
      `[t=${elapsed.toFixed(1)}s] connected=${stats.connected}/${CONCURRENCY} ` +
      `queries=${stats.queries} (${rps.toFixed(0)}/s) ` +
      `queryErr=${stats.queryErrors} connErr=${stats.connErrors}`
    );
  }
}

function printFinal() {
  stats.finishedAt = Date.now();
  const elapsed = (stats.finishedAt - stats.startedAt) / 1000;
  const rps = stats.queries / elapsed;

  const sorted = [...stats.latencies].sort((a, b) => a - b);
  const p50 = quantile(sorted, 0.50);
  const p95 = quantile(sorted, 0.95);
  const p99 = quantile(sorted, 0.99);
  const max = sorted[sorted.length - 1] || 0;

  const perClient = stats.perClient.filter(n => n > 0).sort((a, b) => a - b);
  const pcMin = perClient[0] || 0;
  const pcMax = perClient[perClient.length - 1] || 0;
  const pcAvg = perClient.length ? stats.queries / perClient.length : 0;

  console.log('');
  console.log('================ RESULTS ================');
  console.log(`DSN:              ${redact(DSN)}`);
  console.log(`Query:            ${QUERY}`);
  console.log(`Clients:          ${CONCURRENCY} (connected ${stats.connected})`);
  console.log(`Duration:         ${elapsed.toFixed(2)} s`);
  console.log(`Queries:          ${stats.queries}`);
  console.log(`Throughput:       ${rps.toFixed(0)} q/s`);
  console.log(`Per-client (q):   min=${pcMin} avg=${pcAvg.toFixed(0)} max=${pcMax}`);
  console.log('Latency:');
  console.log(`  p50 = ${fmtNs(p50)}`);
  console.log(`  p95 = ${fmtNs(p95)}`);
  console.log(`  p99 = ${fmtNs(p99)}`);
  console.log(`  max = ${fmtNs(max)}`);
  console.log(`Connection errors: ${stats.connErrors}`);
  console.log(`Query errors:      ${stats.queryErrors}`);
  console.log('=========================================');
}

function redact(dsn) { return dsn.replace(/:[^:@/]*@/, ':****@'); }

async function main() {
  console.log(`poolsmith stress: ${CONCURRENCY} clients, ${DURATION_MS/1000}s against ${redact(DSN)}`);
  console.log(`query: ${QUERY}   ramp: ${RAMP_MS}ms`);

  stats.startedAt = Date.now();
  const deadline = stats.startedAt + RAMP_MS + DURATION_MS;

  const reporter = periodicReport();
  const workers = [];
  for (let i = 0; i < CONCURRENCY; i++) {
    workers.push(runClient(i, deadline));
    // Small stagger so we don't hammer TCP SYN at once.
    if (RAMP_MS > 0 && i < CONCURRENCY - 1) {
      await new Promise(r => setTimeout(r, RAMP_MS / CONCURRENCY));
    }
  }
  await Promise.all(workers);
  await reporter.catch(() => {});
  printFinal();
}

process.on('SIGINT', () => { printFinal(); process.exit(130); });

main().catch(e => {
  console.error('fatal:', e);
  process.exit(1);
});
