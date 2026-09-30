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
	for _, c := range []struct{ query, text, args string }{
		{"UPDATE u SET p = %p WHERE n = %n AND d = %d OR u = %u",
			"UPDATE u SET p = $1 WHERE n = $2 AND d = $3 OR u = $4", "[{X}h Alice Example.org Alice@Example.org]"},
		{"WHERE n = '%n' AND d = \"%d\" AND a = 'Y'",
			"WHERE n = $1 AND d = $2 AND a = 'Y'", "[Alice Example.org]"},
		{"WHERE n = '%{user | username}' AND d = '%{user|domain|lower}' AND u = %{user}",
			"WHERE n = $1 AND d = $2 AND u = $3", "[Alice example.org Alice@Example.org]"},
		{"WHERE u = '%Lu' AND n = %Un AND d = %{domain} AND h = %{hash}",
			"WHERE u = $1 AND n = $2 AND d = $3 AND h = $4", "[alice@example.org ALICE Example.org {X}h]"},
		{"SET p = %h, q = '%{hash | noscheme}'", "SET p = $1, q = $2", "[h h]"},
		{"SELECT '/var/vmail/%d/%n' AS home, 'it''s %n' AS s, 7 %% 2 WHERE u LIKE '%%%u'",
			"SELECT $1 AS home, $2 AS s, 7 % 2 WHERE u LIKE $3", "[/var/vmail/Example.org/Alice it's Alice %Alice@Example.org]"},
	} {
		q, err := ParseQuery(c.query, drivers["pgsql"].bind)
		if err != nil {
			t.Errorf("%q: %v", c.query, err)
			continue
		}
		if q.text != c.text {
			t.Errorf("%q: %q, want %q", c.query, q.text, c.text)
		}
		if got := fmt.Sprint(q.args("Alice@Example.org", "{X}h")); got != c.args {
			t.Errorf("%q: args %s, want %s", c.query, got, c.args)
		}
	}
	if got := fmt.Sprint(mustParse(t, "%u %n %{user|domain}").args("alice", "")); got != "[alice alice ]" {
		t.Errorf("args of a user without a domain: %s", got)
	}
	for _, bad := range []string{"WHERE u = %w", "LIKE 'a%'", "WHERE u = %", "WHERE u = '%u", "%{user",
		"%{user|substr(0,3)}", "%{hash|lower}", "%{home}", "%Lp", "%Xu"} {
		if _, err := ParseQuery(bad, drivers["mysql"].bind); err == nil {
			t.Errorf("%q parsed", bad)
		} else {
			t.Logf("%q: %v", bad, err)
		}
	}
}

func mustParse(t *testing.T, query string) Query {
	t.Helper()
	q, err := ParseQuery(query, drivers["sqlite"].bind)
	if err != nil {
		t.Fatal(err)
	}
	return q
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

// setupSQL fills db with rows and serves it with the queries given.
func setupSQL(t *testing.T, db testDB, sel, update string) (*Server, *sql.DB) {
	t.Helper()
	backend, conn, err := openSQL(t, db, sel, update)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.DB.Close() })
	return &Server{Backend: backend, Limit: NewLimiter(failedTries, failedWindow), MinLength: 8,
		Log: log.New(io.Discard, "", 0)}, conn
}

// openSQL fills db with rows and opens it with the queries given, sel without its lock.
func openSQL(t *testing.T, db testDB, sel, update string) (*SQL, *sql.DB, error) {
	t.Helper()
	conn, err := sql.Open(drivers[db.driver].name, db.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	for _, stmt := range []string{
		"DROP TABLE IF EXISTS users",
		"CREATE TABLE users (username VARCHAR(64), domain VARCHAR(64), password VARCHAR(255) NOT NULL, PRIMARY KEY (username, domain))",
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
	conf := fmt.Sprintf("# the users table\ndriver = %s\ndsn = %s\n\nselect = %s%s\nupdate = %s\n",
		db.driver, db.dsn, sel, db.lock, update)
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	backend, err := OpenSQL(path, testHasher{}, "TEST", "TEST")
	return backend, conn, err
}

func stored(t *testing.T, conn *sql.DB) [][3]string {
	t.Helper()
	rs, err := conn.Query("SELECT username, domain, password FROM users ORDER BY domain, username")
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

const (
	oneSelect = "SELECT password FROM users WHERE username = %n AND domain = %d"
	oneUpdate = "UPDATE users SET password = %p WHERE username = %n AND domain = %d"
)

func TestSQLChange(t *testing.T) {
	for _, db := range testDBs(t) {
		t.Run(db.driver, func(t *testing.T) {
			for _, c := range []struct{ user, old string }{
				{"alice@example.org", "old-secret"},
				{"bob@example.org", "bobs"},
			} {
				s, conn := setupSQL(t, db, oneSelect, oneUpdate)
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
				{"two rows", "UPDATE users SET password = %p WHERE username = %n", "alice@example.org", "old-secret",
					"500 Server error, password not changed"},
			} {
				s, conn := setupSQL(t, db, oneSelect, c.update)
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
		if _, err := OpenSQL(path, testHasher{}, "TEST", "TEST"); err == nil {
			t.Errorf("%s: taken", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

// changed runs a change for user and reports whether the server took it.
func changed(t *testing.T, s *Server, user, old string) bool {
	t.Helper()
	got := converse(t, s, "user "+user, "pass "+old, "newpass fresh secret", "quit")
	return got[len(got)-1] == "200 Bye"
}

func TestSQLSelectColumns(t *testing.T) {
	for _, db := range testDBs(t) {
		t.Run(db.driver, func(t *testing.T) {
			for _, c := range []struct {
				name, sel, user, old string
				ok                   bool
			}{
				{"extra fields", "SELECT username AS user, password, domain AS userdb_home FROM users WHERE username = %n AND domain = %d",
					"alice@example.org", "old-secret", true},
				{"password_noscheme of a bare hash", "SELECT domain, password AS password_noscheme FROM users WHERE username = %n AND domain = %d",
					"bob@example.org", "bobs", true},
				{"password_noscheme of a prefixed hash", "SELECT domain, password AS password_noscheme FROM users WHERE username = %n AND domain = %d",
					"alice@example.org", "old-secret", false},
			} {
				s, conn := setupSQL(t, db, c.sel, oneUpdate)
				before := stored(t, conn)
				if got := changed(t, s, c.user, c.old); got != c.ok {
					t.Errorf("%s: changed %v, want %v", c.name, got, c.ok)
				}
				if after := stored(t, conn); slices.Equal(after, before) == c.ok {
					t.Errorf("%s: rows %q after %q", c.name, after, before)
				}
			}
			for name, sel := range map[string]string{
				"no password":                   "SELECT username, domain FROM users WHERE username = %n AND domain = %d",
				"two passwords":                 "SELECT password, password AS password_noscheme FROM users WHERE username = %n AND domain = %d",
				"a lone column of another name": "SELECT password AS pw FROM users WHERE username = %n AND domain = %d",
				"another case":                  "SELECT domain, password AS \"Password\" FROM users WHERE username = %n AND domain = %d",
			} {
				if _, _, err := openSQL(t, db, sel, oneUpdate); err == nil {
					t.Errorf("%s: taken", name)
				} else {
					t.Logf("%s: %v", name, err)
				}
			}
		})
	}
}

// TestSQLDovecotQueries takes queries as a dovecot-sql.conf.ext or 2.4's passdb sql writes them.
func TestSQLDovecotQueries(t *testing.T) {
	for _, db := range testDBs(t) {
		t.Run(db.driver, func(t *testing.T) {
			for _, c := range []struct{ name, sel, update, user string }{
				{"2.3", "SELECT username, domain, password FROM users WHERE username = '%n' AND domain = '%d'",
					"UPDATE users SET password = '%p' WHERE username = '%n' AND domain = '%d'", "alice@example.org"},
				{"2.4", "SELECT username, domain, password, '/var/vmail/%{user | domain}/%{user | username}' AS userdb_home " +
					"FROM users WHERE username = '%{user | username}' AND domain = '%{user | domain}'",
					"UPDATE users SET password = '%p' WHERE username = '%{user | username}' AND domain = '%{user | domain}'",
					"alice@example.org"},
				{"lower", "SELECT password FROM users WHERE username = '%{user | username | lower}' AND domain = '%{user | domain | lower}'",
					"UPDATE users SET password = %p WHERE username = '%Ln' AND domain = '%Ld'", "Alice@Example.ORG"},
			} {
				s, conn := setupSQL(t, db, c.sel, c.update)
				before := stored(t, conn)
				if !changed(t, s, c.user, "old-secret") {
					t.Errorf("%s: not changed", c.name)
				}
				want := slices.Clone(before)
				want[1][2] = hashed("fresh secret")
				if after := stored(t, conn); !slices.Equal(after, want) {
					t.Errorf("%s: rows %q, want %q", c.name, after, want)
				}
			}
		})
	}
}

func TestSQLBareHash(t *testing.T) {
	for _, db := range testDBs(t) {
		t.Run(db.driver, func(t *testing.T) {
			s, conn := setupSQL(t, db, oneSelect, "UPDATE users SET password = %h WHERE username = %n AND domain = %d")
			before := stored(t, conn)
			if !changed(t, s, "alice@example.org", "old-secret") {
				t.Fatal("not changed")
			}
			want := slices.Clone(before)
			want[1][2] = strings.TrimPrefix(hashed("fresh secret"), "{TEST}")
			if after := stored(t, conn); !slices.Equal(after, want) {
				t.Errorf("rows %q, want %q", after, want)
			}
			// The bare hash is read back under -default-scheme.
			if ok, err := s.Backend.Verify("alice@example.org", "fresh secret"); !ok || err != nil {
				t.Errorf("verify: %v, %v", ok, err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "sql.conf")
	conf := "driver = sqlite\ndsn = x\nselect = SELECT password FROM users WHERE u = %u\nupdate = UPDATE users SET password = %{hash | noscheme} WHERE u = %u\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQL(path, testHasher{}, "SHA512-CRYPT", "TEST"); err == nil {
		t.Error("a bare hash of another scheme than the default taken")
	} else {
		t.Log(err)
	}
}
