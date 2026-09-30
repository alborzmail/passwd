package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseQuery(t *testing.T) {
	q, err := ParseQuery("UPDATE u SET p = %p WHERE n = %n AND d = %d OR u = %u", drivers["pgsql"].bind)
	if err != nil {
		t.Fatal(err)
	}
	if want := "UPDATE u SET p = $1 WHERE n = $2 AND d = $3 OR u = $4"; q.text != want {
		t.Errorf("%q, want %q", q.text, want)
	}
	if got, want := fmt.Sprint(q.args("alice@example.org", "{X}h")), "[{X}h alice example.org alice@example.org]"; got != want {
		t.Errorf("args %s, want %s", got, want)
	}
	if got := fmt.Sprint(q.args("alice", "{X}h")); got != "[{X}h alice  alice]" {
		t.Errorf("args of a user without a domain: %s", got)
	}
	for _, bad := range []string{"WHERE u = %w", "LIKE 'a%'", "WHERE u = %"} {
		if _, err := ParseQuery(bad, drivers["mysql"].bind); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// testDB is a database the SQL tests run against, emptied for each.
type testDB struct {
	driver, dsn string
	// lock makes the select hold the row until the transaction ends; SQLite's is _txlock.
	lock string
}

// testDBs are SQLite when it is built in, and PostgreSQL and MySQL where $PGSQL_DSN and
// $MYSQL_DSN name one.
func testDBs(t *testing.T) []testDB {
	var dbs []testDB
	if slices.Contains(sql.Drivers(), "sqlite") {
		dbs = append(dbs, testDB{"sqlite", "file:" + filepath.Join(t.TempDir(), "users.db") + "?_txlock=immediate", ""})
	}
	for _, d := range []struct{ driver, env string }{{"pgsql", "PGSQL_DSN"}, {"mysql", "MYSQL_DSN"}} {
		if dsn := os.Getenv(d.env); dsn != "" {
			dbs = append(dbs, testDB{d.driver, dsn, " FOR UPDATE"})
		}
	}
	if len(dbs) == 0 {
		t.Skip("no database: build with -tags sqlite, or set $PGSQL_DSN or $MYSQL_DSN")
	}
	return dbs
}

var rows = [][3]string{
	{"alice", "example.org", hashed("old-secret")},
	{"bob", "example.org", strings.TrimPrefix(hashed("bobs"), "{TEST}")},
	{"alice", "example.net", hashed("other")},
}

// setupSQL fills db with rows and serves it with the update given.
func setupSQL(t *testing.T, db testDB, update string) (*Server, *sql.DB) {
	t.Helper()
	conn, err := sql.Open(drivers[db.driver].name, db.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	for _, stmt := range []string{
		"DROP TABLE IF EXISTS users",
		"CREATE TABLE users (name VARCHAR(64), domain VARCHAR(64), password VARCHAR(255) NOT NULL, PRIMARY KEY (name, domain))",
	} {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range rows {
		b := drivers[db.driver].bind
		if _, err := conn.Exec(fmt.Sprintf("INSERT INTO users VALUES (%s, %s, %s)", b(1), b(2), b(3)), r[0], r[1], r[2]); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "sql.conf")
	conf := fmt.Sprintf("# the users table\ndriver = %s\ndsn = %s\n\nselect = SELECT password FROM users WHERE name = %%n AND domain = %%d%s\nupdate = %s\n",
		db.driver, db.dsn, db.lock, update)
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	backend, err := OpenSQL(path, testHasher{}, "TEST")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.DB.Close() })
	return &Server{Backend: backend, Limit: NewLimiter(failedTries, failedWindow), MinLength: 8,
		Log: log.New(io.Discard, "", 0)}, conn
}

func stored(t *testing.T, conn *sql.DB) [][3]string {
	t.Helper()
	rs, err := conn.Query("SELECT name, domain, password FROM users ORDER BY domain, name")
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out [][3]string
	for rs.Next() {
		var r [3]string
		if err := rs.Scan(&r[0], &r[1], &r[2]); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if len(out) != len(rows) {
		t.Fatalf("%d rows stored, want %d", len(out), len(rows))
	}
	return out
}

const oneUpdate = "UPDATE users SET password = %p WHERE name = %n AND domain = %d"

func TestSQLChange(t *testing.T) {
	for _, db := range testDBs(t) {
		t.Run(db.driver, func(t *testing.T) {
			for _, c := range []struct{ user, old string }{
				{"alice@example.org", "old-secret"},
				{"bob@example.org", "bobs"},
			} {
				s, conn := setupSQL(t, db, oneUpdate)
				before := stored(t, conn)
				got := converse(t, s, "user "+c.user, "pass "+c.old, "newpass fresh secret", "quit")
				if got[len(got)-1] != "200 Bye" {
					t.Fatalf("%s: replies %q", c.user, got)
				}
				name, domain, _ := strings.Cut(c.user, "@")
				for i, r := range stored(t, conn) {
					want := before[i]
					if r[0] == name && r[1] == domain {
						want[2] = hashed("fresh secret")
					}
					if r != want {
						t.Errorf("%s: row %q, want %q", c.user, r, want)
					}
				}
			}
		})
	}
}

func TestSQLRefusalsChangeNothing(t *testing.T) {
	for _, db := range testDBs(t) {
		t.Run(db.driver, func(t *testing.T) {
			for _, c := range []struct {
				name, update, user, old, last string
			}{
				{"wrong password", oneUpdate, "alice@example.org", "wrong", "500 Old password is incorrect"},
				{"unknown user", oneUpdate, "carol@example.org", "wrong", "500 Old password is incorrect"},
				{"two rows", "UPDATE users SET password = %p WHERE name = %n", "alice@example.org", "old-secret",
					"500 Server error, password not changed"},
			} {
				s, conn := setupSQL(t, db, c.update)
				before := stored(t, conn)
				got := converse(t, s, "user "+c.user, "pass "+c.old, "newpass fresh secret")
				if got[len(got)-1] != c.last {
					t.Errorf("%s: replies %q, want the last %q", c.name, got, c.last)
				}
				if after := stored(t, conn); !slices.Equal(after, before) {
					t.Errorf("%s: rows %q, want %q", c.name, after, before)
				}
			}
		})
	}
}

func TestSQLConfRefused(t *testing.T) {
	for name, conf := range map[string]string{
		"unknown key":        "driver = sqlite\ndsn = x\nselect = SELECT password FROM users WHERE u = %u\nupdate = UPDATE users SET password = %p WHERE u = %u\nport = 1\n",
		"missing update":     "driver = sqlite\ndsn = x\nselect = SELECT password FROM users WHERE u = %u\n",
		"no hash":            "driver = sqlite\ndsn = x\nselect = SELECT password FROM users WHERE u = %u\nupdate = UPDATE users SET password = 'x' WHERE u = %u\n",
		"no user":            "driver = sqlite\ndsn = x\nselect = SELECT password FROM users\nupdate = UPDATE users SET password = %p WHERE u = %u\n",
		"a Go driver's name": "driver = pgx\ndsn = x\nselect = SELECT password FROM users WHERE u = %u\nupdate = UPDATE users SET password = %p WHERE u = %u\n",
	} {
		path := filepath.Join(t.TempDir(), "sql.conf")
		if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQL(path, testHasher{}, "TEST"); err == nil {
			t.Errorf("%s: taken", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}
