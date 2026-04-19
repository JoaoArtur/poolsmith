package classify

import "testing"

func TestAnalyze(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want Analysis
	}{
		// reads
		{"simple select", "SELECT 1", Analysis{RouteReplica, false}},
		{"select with from", "SELECT * FROM users WHERE id = 1", Analysis{RouteReplica, false}},
		{"lowercase select", "select 1", Analysis{RouteReplica, false}},
		{"mixed case select", "SeLeCt 1", Analysis{RouteReplica, false}},
		{"leading whitespace", "   \n\t SELECT 1", Analysis{RouteReplica, false}},
		{"leading line comment", "-- hello\nSELECT 1", Analysis{RouteReplica, false}},
		{"leading block comment", "/* ignore */ SELECT 1", Analysis{RouteReplica, false}},
		{"table", "TABLE users", Analysis{RouteReplica, false}},
		{"values", "VALUES (1), (2)", Analysis{RouteReplica, false}},
		{"show", "SHOW search_path", Analysis{RouteReplica, false}},
		{"cte select only", "WITH x AS (SELECT 1) SELECT * FROM x", Analysis{RouteReplica, false}},

		// writes
		{"insert", "INSERT INTO t VALUES (1)", Analysis{RoutePrimary, false}},
		{"update", "UPDATE t SET a = 1", Analysis{RoutePrimary, false}},
		{"delete", "DELETE FROM t WHERE id = 1", Analysis{RoutePrimary, false}},
		{"merge", "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = 1", Analysis{RoutePrimary, false}},
		{"cte with insert", "WITH x AS (INSERT INTO t VALUES(1) RETURNING *) SELECT * FROM x", Analysis{RoutePrimary, false}},
		{"cte with update", "WITH x AS (UPDATE t SET a=1 RETURNING *) SELECT * FROM x", Analysis{RoutePrimary, false}},
		{"cte with delete", "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x", Analysis{RoutePrimary, false}},
		{"select for update", "SELECT * FROM t FOR UPDATE", Analysis{RoutePrimary, false}},
		{"select for share", "SELECT * FROM t FOR SHARE", Analysis{RoutePrimary, false}},
		{"select for no key update", "SELECT * FROM t FOR NO KEY UPDATE", Analysis{RoutePrimary, false}},
		{"select for key share", "SELECT * FROM t FOR KEY SHARE", Analysis{RoutePrimary, false}},
		{"select into", "SELECT a, b INTO newtab FROM t", Analysis{RoutePrimary, false}},

		// transaction control
		{"begin", "BEGIN", Analysis{RoutePrimary, false}},
		{"start transaction", "START TRANSACTION", Analysis{RoutePrimary, false}},
		{"commit", "COMMIT", Analysis{RoutePrimary, false}},
		{"rollback", "ROLLBACK", Analysis{RoutePrimary, false}},
		{"savepoint", "SAVEPOINT s1", Analysis{RoutePrimary, false}},
		{"release", "RELEASE SAVEPOINT s1", Analysis{RoutePrimary, false}},

		// copy
		{"copy from", "COPY t FROM STDIN", Analysis{RoutePrimary, false}},
		{"copy to", "COPY t TO STDOUT", Analysis{RouteReplica, false}},

		// DDL (pin)
		{"create table", "CREATE TABLE t(id int)", Analysis{RouteDDL, true}},
		{"alter table", "ALTER TABLE t ADD COLUMN x int", Analysis{RouteDDL, true}},
		{"drop table", "DROP TABLE t", Analysis{RouteDDL, true}},
		{"truncate", "TRUNCATE t", Analysis{RouteDDL, true}},
		{"grant", "GRANT SELECT ON t TO u", Analysis{RouteDDL, true}},
		{"revoke", "REVOKE SELECT ON t FROM u", Analysis{RouteDDL, true}},
		{"vacuum bare", "VACUUM", Analysis{RouteDDL, true}},
		{"analyze bare", "ANALYZE t", Analysis{RouteDDL, true}},
		{"reindex", "REINDEX TABLE t", Analysis{RouteDDL, true}},
		{"cluster", "CLUSTER t", Analysis{RouteDDL, true}},
		{"comment", "COMMENT ON TABLE t IS 'x'", Analysis{RouteDDL, true}},
		{"refresh", "REFRESH MATERIALIZED VIEW v", Analysis{RouteDDL, true}},
		{"do block", "DO $$ BEGIN NULL; END $$", Analysis{RouteDDL, true}},

		// session-pinning primary
		{"listen", "LISTEN ch", Analysis{RoutePrimary, true}},
		{"unlisten", "UNLISTEN ch", Analysis{RoutePrimary, true}},
		{"notify", "NOTIFY ch", Analysis{RoutePrimary, true}},
		{"set session", "SET search_path TO public", Analysis{RoutePrimary, true}},
		{"set session explicit", "SET SESSION timezone TO 'UTC'", Analysis{RoutePrimary, true}},
		{"set local", "SET LOCAL timezone TO 'UTC'", Analysis{RoutePrimary, false}},
		{"reset", "RESET search_path", Analysis{RoutePrimary, true}},
		{"lock", "LOCK TABLE t", Analysis{RoutePrimary, true}},
		{"prepare", "PREPARE p AS SELECT 1", Analysis{RoutePrimary, true}},
		{"deallocate", "DEALLOCATE p", Analysis{RoutePrimary, true}},
		{"discard", "DISCARD ALL", Analysis{RoutePrimary, true}},
		{"declare cursor", "DECLARE c CURSOR FOR SELECT 1", Analysis{RoutePrimary, true}},
		{"create temp table", "CREATE TEMP TABLE t(id int)", Analysis{RoutePrimary, true}},
		{"create temporary table", "CREATE TEMPORARY TABLE t(id int)", Analysis{RoutePrimary, true}},
		{"create global temp table", "CREATE GLOBAL TEMP TABLE t(id int)", Analysis{RoutePrimary, true}},

		// explain
		{"explain select", "EXPLAIN SELECT 1", Analysis{RouteReplica, false}},
		{"explain insert no analyze", "EXPLAIN INSERT INTO t VALUES(1)", Analysis{RouteReplica, false}},
		{"explain analyze select", "EXPLAIN ANALYZE SELECT 1", Analysis{RouteReplica, false}},
		{"explain analyze insert", "EXPLAIN ANALYZE INSERT INTO t VALUES(1)", Analysis{RoutePrimary, false}},
		{"explain analyze update", "EXPLAIN ANALYZE UPDATE t SET a=1", Analysis{RoutePrimary, false}},
		{"explain parens analyze", "EXPLAIN (ANALYZE, BUFFERS) SELECT 1", Analysis{RouteReplica, false}},
		{"explain parens analyze insert", "EXPLAIN (ANALYZE, BUFFERS) INSERT INTO t VALUES(1)", Analysis{RoutePrimary, false}},
		{"explain verbose", "EXPLAIN VERBOSE SELECT 1", Analysis{RouteReplica, false}},

		// literal hiding
		{"dollar quoted hides ddl", "SELECT $$ CREATE TABLE fake $$", Analysis{RouteReplica, false}},
		{"dollar tag hides ddl", "SELECT $tag$ DROP TABLE fake $tag$", Analysis{RouteReplica, false}},
		{"string hides ddl", "SELECT 'it''s INSERT'", Analysis{RouteReplica, false}},
		{"string hides for update", "SELECT 'FOR UPDATE' FROM t", Analysis{RouteReplica, false}},
		{"quoted ident hides keyword", `SELECT "INSERT" FROM t`, Analysis{RouteReplica, false}},
		{"comment hides ddl", "SELECT 1 /* CREATE TABLE fake */", Analysis{RouteReplica, false}},
		{"line comment hides ddl", "SELECT 1 -- CREATE TABLE fake\n", Analysis{RouteReplica, false}},

		// hints
		{"hint primary", "/*+ primary */ SELECT 1", Analysis{RoutePrimary, false}},
		{"hint replica", "/*+ replica */ INSERT INTO t VALUES(1)", Analysis{RouteReplica, false}},
		{"hint ddl", "/*+ ddl */ VACUUM", Analysis{RouteDDL, true}},
		{"hint pin forces pin", "/*+ pin */ SELECT 1", Analysis{RouteReplica, true}},
		{"hint primary+pin", "/*+ primary pin */ SELECT 1", Analysis{RoutePrimary, true}},
		{"hint uppercase", "/*+ PRIMARY */ SELECT 1", Analysis{RoutePrimary, false}},
		{"hint mixed", "/*+ Replica, Pin */ SELECT 1", Analysis{RouteReplica, true}},
		{"no hint plain comment", "/* not a hint primary */ SELECT 1", Analysis{RouteReplica, false}},

		// multi-statement
		{"multi select+insert", "SELECT 1; INSERT INTO t VALUES(1)", Analysis{RoutePrimary, false}},
		{"multi select+ddl", "SELECT 1; CREATE TABLE t()", Analysis{RouteDDL, true}},
		{"multi trailing semicolon", "SELECT 1;", Analysis{RouteReplica, false}},
		{"multi leading semicolons", ";;SELECT 1", Analysis{RouteReplica, false}},
		{"multi insert+set", "INSERT INTO t VALUES(1); SET foo = 1", Analysis{RoutePrimary, true}},
		{"multi select+select", "SELECT 1; SELECT 2", Analysis{RouteReplica, false}},
		{"multi ddl+select", "CREATE TABLE t(); SELECT 1", Analysis{RouteDDL, true}},

		// edge / fallbacks
		{"empty", "", Analysis{RoutePrimary, false}},
		{"whitespace", "   \n\t  ", Analysis{RoutePrimary, false}},
		{"only comments", "/* hi */ -- there\n", Analysis{RoutePrimary, false}},
		{"only semicolons", ";;;", Analysis{RoutePrimary, false}},
		{"unknown verb", "FOOBAR something", Analysis{RoutePrimary, false}},
		{"numbers only", "123 456", Analysis{RoutePrimary, false}},

		// scanning robustness
		{"unterminated string", "SELECT 'unterminated", Analysis{RouteReplica, false}},
		{"unterminated block comment", "/* unterminated", Analysis{RoutePrimary, false}},
		{"unterminated dollar", "SELECT $$ open", Analysis{RouteReplica, false}},
		{"nested block comment", "/* a /* b */ c */ SELECT 1", Analysis{RouteReplica, false}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Analyze(tc.sql)
			if got != tc.want {
				t.Fatalf("Analyze(%q) = %+v; want %+v", tc.sql, got, tc.want)
			}
		})
	}
}

func TestAnalyzeZeroAllocsSelect(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_ = Analyze("SELECT 1")
	})
	if allocs > 0 {
		t.Fatalf("Analyze(SELECT 1) allocated %v times; want 0", allocs)
	}
}

func TestAnalyzeZeroAllocsInsert(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_ = Analyze("INSERT INTO t VALUES (1)")
	})
	if allocs > 0 {
		t.Fatalf("Analyze insert allocated %v times; want 0", allocs)
	}
}

func BenchmarkAnalyze_SelectSimple(b *testing.B) {
	s := "SELECT 1"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Analyze(s)
	}
}

func BenchmarkAnalyze_InsertSimple(b *testing.B) {
	s := "INSERT INTO t VALUES (1)"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Analyze(s)
	}
}

func BenchmarkAnalyze_CteWithInsert(b *testing.B) {
	s := "WITH x AS (INSERT INTO t VALUES(1) RETURNING *) SELECT * FROM x"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Analyze(s)
	}
}

func BenchmarkAnalyze_CreateTable(b *testing.B) {
	s := "CREATE TABLE t(id int primary key, name text)"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Analyze(s)
	}
}

func BenchmarkAnalyze_WithComments(b *testing.B) {
	s := "/* app=api user=42 */ -- trace\nSELECT id, name FROM users WHERE id = $1"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Analyze(s)
	}
}

func BenchmarkAnalyze_HintComment(b *testing.B) {
	s := "/*+ primary */ SELECT id FROM users WHERE id = $1"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Analyze(s)
	}
}
