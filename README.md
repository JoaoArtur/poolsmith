# Poolsmith

**One binary that replaces PgBouncer + HAProxy for most PostgreSQL
deployments.** Transaction-mode multiplexing that doesn't break DDL,
`LISTEN/NOTIFY`, `SET`, prepared statements or multi-tenant `search_path`,
plus read/write splitting across replicas — all in a ~4 MB static Go
binary.

## The problem Poolsmith solves

```
                    ┌─────────────────────────── TYPICAL STACK ──┐
   App ──TCP──► HAProxy ──► PgBouncer ──► Primary
                   │                          │
                   └──► PgBouncer-r ──► Replica (reads)
                   └──► direct conn ──► Primary (DDL, LISTEN, SET)
                     4 moving parts, 3 DSNs in your app config.
```

```
                    ┌──────────────────── WITH POOLSMITH ────────┐
   App ──TCP──► Poolsmith ──► Primary  (writes, DDL, LISTEN, SET)
                    │
                    └─────────► Replica (plain SELECTs)
                        1 deployment, 1 DSN, auto-routed.
```

If you're running a multi-tenant SaaS (per-schema per tenant, dozens to
thousands of schemas), Poolsmith was built for you: one shared connection
pool to Postgres, but each client sees its own `search_path` applied
transparently on every checkout.

## Why it matters

Transaction-mode pooling is the only way to keep Postgres happy under load
— but vanilla PgBouncer transaction mode **breaks** things apps actually
rely on:

- Prepared statements named on the client side (`Parse` + later `Bind`)
- `LISTEN/NOTIFY`
- `SET search_path`, `SET TimeZone`, `SET role`
- `CREATE TEMP TABLE` that must survive the whole session
- `PREPARE` / `DEALLOCATE` SQL
- `LOCK TABLE` held across statements

Poolsmith handles all of those **and** multiplexes everything else tightly.
The classifier inspects every statement; if it needs session state, the
current backend is pinned to the client until they disconnect; otherwise
the backend goes back to the shared pool the instant the transaction ends.

## What you get

- **All three pool modes**: `session`, `transaction`, `statement`.
- **Auto session pinning** on DDL, `LISTEN`, `SET` (non-`LOCAL`), `PREPARE`,
  `CREATE TEMP TABLE`, `DO $$ … $$`, `LOCK`, `DECLARE CURSOR`, and advisory
  locks — no code change on the app side.
- **Multi-tenant `search_path` replay**: one shared pool serves many
  tenants; Poolsmith issues `SET search_path TO '<tenant>'` on every
  backend checkout when the session's desired schema doesn't match the
  backend's current state.
- **Prepared-statement rewriting** (PgBouncer 1.21+ style): client
  statement names are mapped to canonical hashes, Parse is injected on
  backend swap, `Close` is deferred. Prod-proven against `whatsmeow`-style
  Go apps that issue hundreds of prepared statements per client.
- **Read/write splitting** across read replicas with passive circuit
  breaker (3 failures / 30 s trips a replica, 10 s probe-retry).
  Read-only SELECTs, `EXPLAIN` (no `ANALYZE`), `SHOW`, and SELECT-only CTEs
  fan out to replicas; everything else, including `SELECT … FOR UPDATE`,
  `WITH … INSERT …`, and `COPY … FROM`, sticks to the primary.
- **Routing hints**: `/*+ primary */`, `/*+ replica */`, `/*+ ddl */` force
  the route when the parser would get it wrong (e.g. `SELECT my_fn()`
  where `my_fn` writes internally — see Caveats).
- **PgBouncer-compatible INI config** (`pool_mode`, `auth_type`,
  `auth_file`, `default_pool_size`, …) so existing tooling keeps working.
- **Raw-text userlist** (`"user" "password"`), hot-reloadable via
  `RELOAD`.
- **Admin console** over SQL: connect to the `poolsmith` virtual database
  with psql and run `SHOW POOLS`, `SHOW DATABASES`, `SHOW SERVERS`,
  `SHOW STATS`, `SHOW CLIENTS`, `SHOW CONFIG`, `SHOW VERSION`, `PAUSE`,
  `RESUME`, `RELOAD`, `SHUTDOWN`. Read-only `SHOW *` also works from any
  database/user session for debugging.
- **MD5 and SCRAM-SHA-256** on both client and upstream sides, RFC 7677
  test-vector verified.
- **Client and upstream TLS** (`disable`/`prefer`/`require`/`verify-*`).
- **Zero-allocation SQL classifier**, < 30 ns per simple SELECT.
- **Structured logs** (slog JSON or text), atomic metrics counters exposed
  through the admin console.

## Scope — what Poolsmith is NOT

Knowing what this tool doesn't do is as important as what it does.

- **Primary failover is out of scope.** Poolsmith trusts the primary to
  exist. If the primary goes down, every write fails until it comes back
  up or some external orchestrator rewrites the `[servers]` block and
  reloads. There is no leader election, no synchronous/async replication
  management, no split-brain protection. Put **Patroni** (or equivalent)
  between Poolsmith and the cluster if you want automated failover —
  Poolsmith will talk to Patroni's rest-endpoint-fronted VIP just like it
  talks to anything else.
- **Read replica health is passive.** A replica is only marked unhealthy
  after real queries start failing. Replication lag is NOT checked;
  Poolsmith won't route reads away from a stale replica just because
  `pg_last_wal_receive_lsn()` is behind. Wire Patroni/pg_auto_failover/your
  own probe for that and tell Poolsmith via `RELOAD` when a replica should
  be removed.
- **No cancellation pass-through yet.** Clients that call
  `pg_cancel_backend()` indirectly through the CancelRequest protocol
  bypass Poolsmith today. Workaround: clients that disconnect when they
  want to cancel work correctly.

## Quick start

```
$ go build -o bin/poolsmith ./cmd/poolsmith
$ bin/poolsmith -config config/poolsmith.ini.example -log-text
```

With a minimal `poolsmith.ini`:

```ini
[poolsmith]
listen_port = 6432
auth_type   = md5
auth_file   = /etc/poolsmith/userlist.txt
pool_mode   = transaction

[servers]
primary = host=10.0.0.1 port=5432 role=primary

[databases]
app = server=primary dbname=app_prod pool_size=20
```

And a `userlist.txt`:

```
"app" "app-password"
```

Then just point your application at `poolsmith:6432/app`. DDL, `LISTEN`,
`PREPARE`, `SET search_path` all continue to work without any client
changes.

## How routing works

```
                   ┌──────────────────────┐
client ──────────▶ │  Poolsmith (6432)    │
                   │   wire protocol      │
                   │        │             │
                   │        ▼             │
                   │   SQL classifier     │  ← < 30 ns/SELECT, zero allocs
                   │        │             │
                   │   ┌────┴─────┐       │
                   │   │          │       │
                   │   ▼          ▼       │
                   │  POOL      PIN       │  ← DDL / LISTEN / SET / PREPARE
                   │ (shared)  (session)  │
                   └───┬──────────┬───────┘
                       │          │
                       ▼          ▼
                   primary    primary
                  (replicas  (same backend
                   for reads) for the rest
                              of the client
                              session)
```

`SELECT … FOR UPDATE`, `WITH x AS (INSERT …)`, `COPY … FROM`, and
`SELECT … INTO` are correctly classified as writes. `EXPLAIN ANALYZE
<write>` also goes to the primary. `SELECT $$ CREATE TABLE fake $$` does
NOT get misclassified — dollar-quoted literals, single- and double-quoted
strings, and nested block comments are all skipped by the scanner.

You can override any decision with a leading hint comment:

```sql
/*+ primary */ SELECT last_inserted_id()
/*+ replica */ SELECT count(*) FROM orders
/*+ ddl     */ SELECT pg_reload_conf()
```

## Admin console

```
$ psql -h localhost -p 6432 -U postgres poolsmith
poolsmith=# SHOW POOLS;
 database | user | server  | cl_active | cl_waiting | sv_active | sv_idle | sv_total | pool_mode
----------+------+---------+-----------+------------+-----------+---------+----------+-------------
 app      | app  | primary |         3 |          0 |         3 |         2 |        5 | transaction

poolsmith=# SHOW DATABASES;
poolsmith=# SHOW SERVERS;
poolsmith=# SHOW STATS;
poolsmith=# RELOAD;
```

`RELOAD` re-reads the INI and the userlist without dropping client
connections. `PAUSE` stops accepting new client queries (in-flight queries
complete); `RESUME` releases the pause. `SHUTDOWN` triggers a graceful
close.

## Performance

Classifier benchmarks on an Apple M4 (`go test -bench=.` in
`internal/classify`):

| Benchmark          | ns/op | allocs/op |
|--------------------|-------|-----------|
| `SELECT 1`         | 27.25 |         0 |
| `INSERT …`         | 56.44 |         0 |
| `WITH … INSERT`    | 189.8 |         0 |
| `CREATE TABLE`     | 112.2 |         0 |
| with leading `/* */` comments | 145.9 | 0 |
| `/*+ primary */ …` hint       | 128.4 | 0 |

Wire framing (`internal/wire`) and auth (`internal/auth`) tests pass under
`-race`. SCRAM-SHA-256 is verified against the RFC 7677 test vector.

### End-to-end stress test

`scripts/stress-test.js` spawns N dedicated TCP client connections and
hammers them with `SELECT 1` until the duration elapses. Run from a
developer laptop (Apple M4, Docker Desktop Postgres 16, Poolsmith with
`pool_mode=transaction`, `default_pool_size=30`):

```bash
cd scripts
DSN="postgres://app:app-password@localhost:6432/app" \
  CONCURRENCY=300 DURATION_SEC=20 \
  node stress-test.js
```

Results for **300 concurrent clients × 20 s**:

| Metric                | Value                               |
|-----------------------|-------------------------------------|
| Throughput            | **31 647 q/s** (791 204 queries)    |
| Latency p50           | 7.51 ms                             |
| Latency p95           | 10.58 ms                            |
| Latency p99           | 13.69 ms                            |
| Max latency           | 352.81 ms                           |
| Per-client fairness   | min 2 471 / avg 2 637 / max 2 841   |
| Connection errors     | 0                                   |
| Query errors          | 0                                   |

Mid-stress, `SHOW POOLS` and `SHOW CLIENTS` (queried concurrently via
`psql`) confirmed the multiplexing working as designed:

```
 database |  user  | server  | cl_active | cl_waiting | sv_active | sv_idle | sv_total |  pool_mode
----------+--------+---------+-----------+------------+-----------+---------+----------+-------------
 app      | app    | primary |    30     |    264     |    30     |   0     |    30    | transaction

 active_clients
----------------
     302
```

**300 client connections → 30 real Postgres backends (10×
multiplexing)**, with 264 clients queued on `cl_waiting` taking turns on
the shared pool. When the stress test ended, `sv_active` dropped to `0`
and `sv_idle` filled to `30` — the backends stayed warm, ready to serve
the next burst without paying for another SCRAM handshake.

## Tuning for large connection counts

Poolsmith is designed to keep server-side connections small while accepting
a large number of client connections. The two knobs you care about are
**client-side fan-in** (how many apps/goroutines call Poolsmith) and
**server-side fan-out** (how many TCP connections Poolsmith holds against
Postgres).

### Reference configurations

```ini
;; ──────────────────────────────── 1 000 clients ────────────────────────────
[poolsmith]
listen_port       = 6432
pool_mode         = transaction
default_pool_size = 25          ; per (db, user) pool — 3 pods × 25 ≈ 75 backends
max_client_conn   = 1000
server_idle_timeout    = 600    ; keep idle backends up to 10 min so bursts reuse them
server_lifetime        = 3600
client_login_timeout   = 60
query_wait_timeout     = 120
```

Deploy with **3 replicas** of the container (≈ 333 clients per pod) and
`default_pool_size = 25` per pool. Worst case ~75 real Postgres backends
— 7.5 % of what 1 000 direct app connections would cost.

```ini
;; ──────────────────────────────── 5 000 clients ────────────────────────────
[poolsmith]
listen_port       = 6432
pool_mode         = transaction
default_pool_size = 40          ; 10 pods × 40 = 400 backends max
max_client_conn   = 5000
server_idle_timeout    = 900
server_lifetime        = 3600
query_wait_timeout     = 60     ; fail-fast rather than unbounded queueing
```

Deploy with **10 replicas** and an HPA scaling up to 20. At 5 000 clients
you want Postgres tuned too: `max_connections ≥ 500`,
`shared_buffers ≥ 8 GB`, and `effective_cache_size` matching host RAM.

### Per-pod OS / runtime tuning

| Setting                     | Recommendation                                  |
|-----------------------------|-------------------------------------------------|
| `ulimit -n`                 | ≥ 2 × `max_client_conn` + `default_pool_size`.  |
| `GOMAXPROCS`                | Equal to the container CPU limit.               |
| `GOMEMLIMIT`                | ~90 % of the container memory limit.            |
| `net.core.somaxconn`        | ≥ 1024 on the host — the k8s node sysctl does it. |
| `net.ipv4.tcp_tw_reuse`     | `1` (safe for client-only sockets).             |

The `deploy/k8s/deployment.yaml` in this repo already wires `GOMAXPROCS`
and `GOMEMLIMIT` from the pod limits so you don't have to.

### Horizontal vs. vertical scale

Each Poolsmith pod is a single Go process with its own pool map. Two pods
at `default_pool_size = 25` open **up to 50 backends** against Postgres,
not 25. That's by design — it mirrors how PgBouncer scales. When in doubt,
**horizontal > vertical**: more replicas give you CPU headroom for TLS,
SCRAM, and the classifier's hot path without growing the per-pod pool.

### Quick health check on pressure

Inside your fleet, connect to any DB through Poolsmith and run:

```sql
SHOW POOLS;     -- cl_waiting > 0 means your pool is too small
SHOW STATS;     -- per-db query counts + byte counts
SHOW CLIENTS;   -- total live client sessions per pod
```

`cl_waiting` consistently above zero means clients are blocked acquiring a
backend. Raise `pool_size` before raising `max_client_conn`.

## Docker image

A pre-built image is published to GitLab Container Registry. It's a
`scratch`-based **~4 MB** image — no shell, no libc, just the stripped
static binary.

```bash
docker pull registry.gitlab.com/poolsmith/poolsmith:latest

docker run --rm -p 6432:6432 \
  -v "$PWD/config/poolsmith.ini.example:/etc/poolsmith/poolsmith.ini:ro" \
  -v "$PWD/config/userlist.txt.example:/etc/poolsmith/userlist.txt:ro" \
  registry.gitlab.com/poolsmith/poolsmith:latest
```

Tags:

| Tag       | Meaning                                              |
|-----------|------------------------------------------------------|
| `latest`  | Tracks the tip of `master`.                          |
| `0.1`     | Pinned release.                                      |

## Kubernetes

A single-file manifest is in `deploy/k8s/poolsmith.yaml` — ConfigMap +
Secret + Deployment (2 replicas, `registry.gitlab.com/poolsmith/poolsmith:latest`)
+ Service on port **5432**. Edit the INI inline, set real passwords in the
Secret, then:

```bash
kubectl apply -f deploy/k8s/poolsmith.yaml
```

Apps connect to `poolsmith.<namespace>.svc:5432` as if it were Postgres.
Scale with `kubectl scale deploy/poolsmith --replicas=N`.

## Compared to the alternatives

|                                             | PgBouncer   | PgCat        | Pgpool-II    | **Poolsmith** |
|---------------------------------------------|:-----------:|:------------:|:------------:|:-------------:|
| Transaction-mode DDL / LISTEN / SET working | ❌          | ⚠️ partial   | ⚠️ partial   | ✅            |
| Transaction-mode prepared statements        | ✅ 1.21+     | ✅           | ⚠️            | ✅            |
| Multi-tenant `search_path` replay on share  | ❌          | ❌           | ⚠️            | ✅            |
| Read/write splitting                        | ❌          | ✅           | ✅           | ✅            |
| Passive replica circuit breaker             | ❌          | ⚠️            | ✅           | ✅            |
| Single binary, zero deps                    | ✅ (C)       | ✅ (Rust)     | ❌            | ✅ (Go, 4 MB)  |
| INI config + `userlist.txt` compatible      | —            | partial      | ❌            | ✅            |
| Admin console via SQL (`SHOW POOLS` …)      | ✅          | ✅           | ✅           | ✅            |
| Built-in primary failover                    | ❌          | ❌            | ✅            | ❌ (use Patroni) |
| Cancel pass-through                          | ✅          | ✅           | ✅           | ❌ v1         |

Pick Poolsmith when the single thing you hate most is having to run
PgBouncer + HAProxy + a second direct DSN for DDL. Pick Pgpool-II if you
want a batteries-included bundle including failover. Pick PgCat if you're
already invested in Rust tooling and need aggressive sharding.

## Correctness tests

In addition to the parser's unit suite (+ fuzz), the wire-protocol and auth
packages are covered by `go test -race ./...`:

- `internal/wire` — round-trip framing, startup, error fields, parse
  bodies, backend-key-data, oversize-message rejection.
- `internal/auth` — MD5 + SCRAM-SHA-256 round-trip via `net.Pipe`, plus a
  hard-coded RFC 7677 §3 test vector (user `user`, password `pencil`,
  salt `W22ZaJ0SNY7soEsUEjb6gQ==`, `i=4096`) that verifies
  `ClientProof` + `ServerSignature` byte-for-byte.
- `internal/classify` — the full decision table shown in this README
  lives as a table-driven test, plus an allocs-per-op check that fails if
  the classifier regresses above zero allocations on the hot path.

End-to-end stress (see Performance below) verifies 300 clients × 20 s
routed through a real Postgres 16 land on **30 shared backends (10×
multiplexing)** with zero connection or query errors.

## Caveats

### Stored functions that write are classified as reads

A SELECT that invokes a function the classifier can't see through —
`SELECT charge_customer(42)` where `charge_customer` issues an `INSERT`
internally — is routed to a replica. Three ways to fix it:

- Add a leading hint: `/*+ primary */ SELECT charge_customer(42)`.
- Call the function from a user whose pool has no replicas (per-`[databases]`
  `replicas=` entry), so all its traffic lands on the primary.
- On the roadmap: `conservative_routing = true` that forces any function
  call not on an explicit whitelist to the primary. Open an issue if you
  want this sooner.

### Temp tables in transaction mode

`CREATE TEMP TABLE` is special: the table vanishes when its creating
session ends. With a naive transaction-mode pooler the creating backend
gets returned to the pool after `COMMIT`, any later `SELECT` from that
temp table lands on a different backend, and your app sees
`relation "tmp_x" does not exist`.

Poolsmith's classifier detects `CREATE TEMP TABLE`, `CREATE TEMPORARY`,
and `DECLARE CURSOR` and **auto-pins the current backend to the client
for the rest of its session**. Temp tables Just Work. Caveat: a pinned
client no longer shares its backend, so if your workload creates temp
tables on every transaction across many clients you're effectively back
in session mode. Consider rewriting to CTEs or unlogged tables with
explicit cleanup.

### Session state that doesn't come through SET

Some clients mutate session state through function calls that the
classifier can't catch: `SELECT set_config('foo', 'bar', false)` (GUC
change with `is_local=false`), `SELECT pg_advisory_lock(1234)` without a
matching unlock, `SELECT set_role('admin')`, etc. These leak to the next
client that borrows the same backend.

Poolsmith handles the common cases (`SET`, `PREPARE`, `LISTEN`, `LOCK`,
`DECLARE CURSOR`) via the classifier. Roadmap: `server_reset_query` knob
(PgBouncer-compatible) so operators can run `DISCARD ALL` or a targeted
reset on release. Until then, avoid these patterns in apps that go
through Poolsmith — or pin the whole session with `/*+ ddl */ SELECT 1`
as the first statement after connect if you really need them.

### Primary failover

Poolsmith does **not** promote replicas or re-elect primaries. If your
primary is down and you haven't moved its DNS entry / VIP / Patroni
proxy, writes will fail. See Scope above.

### Query cancellation

v1 does not proxy `CancelRequest` (pid/secret) to upstream backends.
Clients that cancel by closing the TCP connection (the default for most
drivers when a context deadline fires) work correctly. Apps that call
`pg_cancel_backend()` from a *different* connection through Poolsmith
won't hit the in-flight query.

## Repository layout

```
poolsmith/
├── cmd/poolsmith/            # main entrypoint
├── config/                   # example INI + userlist
└── internal/
    ├── admin/                # SHOW POOLS, PAUSE, RESUME, RELOAD, SHUTDOWN
    ├── auth/                 # MD5 + SCRAM-SHA-256, client + server
    ├── classify/             # zero-alloc SQL classifier (route + pin)
    ├── config/               # INI parser + typed config + userlist
    ├── logger/               # slog wrapper
    ├── metrics/              # atomic counters
    ├── pool/                 # backend + pool (per server/db/user)
    ├── prepared/             # prepared-statement rewriter
    ├── proxy/                # listener, client session loop, routing
    ├── tlsutil/              # TLS configs (client + upstream)
    └── wire/                 # postgres v3 protocol: framing + messages
```

Core has **zero external dependencies** — the whole thing builds with
`go build ./...` against the Go 1.22 stdlib.

## License

MIT.
