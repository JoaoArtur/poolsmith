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
