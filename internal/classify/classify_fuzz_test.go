package classify

import "testing"

func FuzzAnalyze(f *testing.F) {
	seeds := []string{
		"",
		";",
		";;;",
		"SELECT 1",
		"select 1",
		"INSERT INTO t VALUES (1)",
		"UPDATE t SET a=1",
		"DELETE FROM t",
		"MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET a=1",
		"WITH x AS (INSERT INTO t VALUES(1) RETURNING *) SELECT * FROM x",
		"CREATE TABLE t(id int)",
		"DROP TABLE t",
		"VACUUM",
		"ANALYZE",
		"EXPLAIN SELECT 1",
		"EXPLAIN ANALYZE INSERT INTO t VALUES(1)",
		"EXPLAIN (ANALYZE, BUFFERS) SELECT 1",
		"SET search_path TO public",
		"SET LOCAL timezone TO 'UTC'",
		"LISTEN ch",
		"PREPARE p AS SELECT 1",
		"DECLARE c CURSOR FOR SELECT 1",
		"CREATE TEMP TABLE t(id int)",
		"COPY t FROM STDIN",
		"COPY t TO STDOUT",
		"DO $$ BEGIN NULL; END $$",
		"SELECT 'it''s INSERT'",
		"SELECT $$ CREATE TABLE fake $$",
		"SELECT $tag$ DROP $tag$",
		"/*+ primary */ SELECT 1",
		"/*+ replica pin */ INSERT INTO t VALUES(1)",
		"/* nested /* block */ comment */ SELECT 1",
		"-- line comment\nSELECT 1",
		"SELECT 1; INSERT INTO t VALUES(1); CREATE TABLE u()",
		"SELECT * FROM t FOR NO KEY UPDATE",
		"  ",
		"\x00\xff\x01",
		"SELECT $$ unterminated",
		"/* unterminated",
		"'unterminated",
		"\"unterminated",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sql string) {
		a := Analyze(sql)
		switch a.Route {
		case RoutePrimary, RouteReplica, RouteDDL:
		default:
			t.Fatalf("Analyze(%q) returned invalid Route %d", sql, a.Route)
		}
	})
}
