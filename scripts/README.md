# stress-test.js

Minimal Node.js stress test — spawns N dedicated TCP connections against the
given DSN and hammers them with a query until the duration elapses.

## Usage

```bash
cd scripts
npm install
DSN="postgres://app:pw@localhost:6432/drivio" \
  CONCURRENCY=300 \
  DURATION_SEC=30 \
  QUERY="SELECT 1" \
  node stress-test.js
```

## Env vars

| Var           | Default                                                  | Notes                                           |
|---------------|----------------------------------------------------------|-------------------------------------------------|
| `DSN`         | `postgres://postgres@localhost:6432/postgres`            | Any standard Postgres URI.                      |
| `CONCURRENCY` | `300`                                                    | Number of simultaneous TCP connections.         |
| `DURATION_SEC`| `15`                                                     | Runtime after ramp-up.                          |
| `QUERY`       | `SELECT 1`                                               | Query each worker runs in a loop.               |
| `RAMP_MS`     | `500`                                                    | Ramp window — workers start spread over this.   |
| `REPORT_SEC`  | `5`                                                      | Periodic status line interval.                  |
| `KEEPALIVE`   | `1`                                                      | `0` to disable TCP keepalive on workers.        |

## Output

Periodic:
```
[t=5.0s] connected=300/300 queries=22310 (4462/s) queryErr=0 connErr=0
```

Final:
```
================ RESULTS ================
DSN:              postgres://app:****@localhost:6432/drivio
Query:            SELECT 1
Clients:          300 (connected 300)
Duration:         30.01 s
Queries:          134512
Throughput:       4482 q/s
Per-client (q):   min=401 avg=448 max=530
Latency:
  p50 = 21.34 ms
  p95 = 41.07 ms
  p99 = 68.12 ms
  max = 213.44 ms
Connection errors: 0
Query errors:      0
=========================================
```

`Per-client` min/max close together = fair load distribution. Big gap = some
workers starved (pool too small, rate limiter, bad classifier decision).
