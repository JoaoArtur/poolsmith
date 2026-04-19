# Poolsmith

Poolsmith is a PostgreSQL connection pooler that replaces PgBouncer while
keeping the features PgBouncer breaks in transaction mode working
transparently.

It speaks the Postgres v3 wire protocol natively, runs as a standalone
deployment, and sits between your application and Postgres exactly where
PgBouncer would. The difference: Poolsmith **classifies every statement**
and promotes the current backend to a pinned session whenever the client
sends DDL, `LISTEN/NOTIFY`, `SET` (non-`LOCAL`), `PREPARE`, temp tables,
`LOCK`, or any other session-level operation. Everything else continues to
multiplex over a small shared pool like you would expect.

The effect: a single DSN, a single client TLS setup, a single connection-
count budget at Postgres — while your migrations, pub/sub, prepared
statements, and `SET search_path` keep working.

## What you get

- **All three pool modes**: `session`, `transaction`, `statement`.
- **Transparent session pinning** when the SQL demands it (DDL, `LISTEN`,
  `SET`, `PREPARE`, `DO $$ … $$`, `LOCK`, …). No code changes on the app side.
- **Read/write splitting** across read replicas with passive circuit breaker.
- **Prepared statement rewriting** for transaction mode (PgBouncer 1.21+
  style): client statement names are mapped to canonical hashes, Parse is
  injected on backend swap, `Close` is deferred.
- **PgBouncer-compatible INI config** (`pool_mode`, `auth_type`, `auth_file`,
  `default_pool_size`, …) so existing tooling keeps working.
- **Raw-text userlist** (`"user" "password"`), hot-reloadable.
- **Admin console** over SQL: connect to the `pgbouncer` (or `poolsmith`)
  virtual database with psql and run `SHOW POOLS`, `SHOW DATABASES`,
  `SHOW SERVERS`, `SHOW STATS`, `SHOW CLIENTS`, `SHOW CONFIG`, `SHOW VERSION`,
  `PAUSE`, `RESUME`, `RELOAD`, `SHUTDOWN`.
- **MD5 and SCRAM-SHA-256** authentication on both client and upstream sides,
  RFC 7677 verified.
- **Client and upstream TLS** (`disable`/`prefer`/`require`/`verify-*`).
- **Zero-allocation SQL classifier**, < 30 ns per simple SELECT.
- **Structured logs** (slog JSON or text), atomic metrics counters exposed
  through the admin console.

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
$ psql -h localhost -p 6432 -U postgres pgbouncer
pgbouncer=# SHOW POOLS;
 database | user | server  | cl_active | cl_waiting | sv_active | sv_idle | sv_total | pool_mode
----------+------+---------+-----------+------------+-----------+---------+----------+-------------
 app      | app  | primary |         3 |          0 |         3 |         2 |        5 | transaction

pgbouncer=# SHOW DATABASES;
pgbouncer=# SHOW SERVERS;
pgbouncer=# SHOW STATS;
pgbouncer=# RELOAD;
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

## Caveats

- Functions that internally issue writes (`SELECT my_fn()` where `my_fn`
  does `INSERT`) are classified as reads. Override with `/*+ primary */`
  or by calling them only on the primary via a dedicated user.
- Temp tables must be created inside a transaction when running in
  transaction mode — otherwise the backend may be reused before your
  session-scoped temp is dropped. Poolsmith auto-pins on `CREATE TEMP` to
  keep temp tables alive for the rest of the client session.
- Query cancellation: v1 does not proxy `CancelRequest` to upstreams yet;
  clients that disconnect instead of calling `pg_cancel_backend()` still
  work as expected.

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
