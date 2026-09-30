package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// sqlTimeout bounds one lookup or one change, the doveadm runs inside it included.
const sqlTimeout = 20 * time.Second

// drivers maps Dovecot's SQL driver names to the Go drivers built in with the same build tag,
// and to how each binds its i-th parameter.
var drivers = map[string]struct {
	name string
	bind func(i int) string
}{
	"pgsql":  {"pgx", func(i int) string { return "$" + strconv.Itoa(i) }},
	"mysql":  {"mysql", func(int) string { return "?" }},
	"sqlite": {"sqlite", func(int) string { return "?" }},
}

// SQL keeps the passwords in the database Dovecot's SQL passdb reads.
type SQL struct {
	DB             *sql.DB
	Select, Update Query
	Hasher         Hasher
	// DefaultScheme is the passdb's, for a password stored without a {SCHEME} prefix.
	DefaultScheme string
}

// A Query is SQL with Dovecot's variables bound as parameters: %u the user, %n its local part,
// %d its domain, and %p the new password's hash.
type Query struct {
	text string
	vars []byte
}

func ParseQuery(query string, bind func(i int) string) (Query, error) {
	var q Query
	var b strings.Builder
	for i := 0; i < len(query); i++ {
		if query[i] != '%' {
			b.WriteByte(query[i])
			continue
		}
		if i++; i == len(query) || !strings.ContainsRune("undp", rune(query[i])) {
			return Query{}, fmt.Errorf("%q: the variables are %%u, %%n, %%d and %%p", query)
		}
		q.vars = append(q.vars, query[i])
		b.WriteString(bind(len(q.vars)))
	}
	q.text = b.String()
	return q, nil
}

func (q Query) args(user, hash string) []any {
	name, domain, _ := strings.Cut(user, "@")
	values := map[byte]string{'u': user, 'n': name, 'd': domain, 'p': hash}
	args := make([]any, len(q.vars))
	for i, v := range q.vars {
		args[i] = values[v]
	}
	return args
}

func (q Query) has(vars string) bool {
	return slices.ContainsFunc(q.vars, func(v byte) bool { return strings.IndexByte(vars, v) >= 0 })
}

// OpenSQL reads a file of driver, dsn, select and update lines, each "key = value", and
// connects to the database.
func OpenSQL(path string, h Hasher, defaultScheme string) (*SQL, error) {
	conf, err := readConf(path, "driver", "dsn", "select", "update")
	if err != nil {
		return nil, err
	}
	driver, ok := drivers[conf["driver"]]
	if !ok {
		return nil, fmt.Errorf("driver %q: give pgsql, mysql or sqlite", conf["driver"])
	}
	s := &SQL{Hasher: h, DefaultScheme: defaultScheme}
	if s.Select, err = ParseQuery(conf["select"], driver.bind); err != nil {
		return nil, err
	}
	if s.Update, err = ParseQuery(conf["update"], driver.bind); err != nil {
		return nil, err
	}
	if !s.Select.has("und") || s.Select.has("p") {
		return nil, errors.New("select: name the user with %u, %n or %d, and no %p")
	}
	if !s.Update.has("und") || !s.Update.has("p") {
		return nil, errors.New("update: name the user with %u, %n or %d, and the hash with %p")
	}
	if !slices.Contains(sql.Drivers(), driver.name) {
		return nil, fmt.Errorf("driver %q is not built in: build with -tags %s", conf["driver"], conf["driver"])
	}
	if s.DB, err = sql.Open(driver.name, conf["dsn"]); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), sqlTimeout)
	defer cancel()
	// Preparing the queries finds a misspelt table or column before the first reader does.
	for name, q := range map[string]Query{"select": s.Select, "update": s.Update} {
		stmt, err := s.DB.PrepareContext(ctx, q.text)
		if err != nil {
			s.DB.Close()
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		stmt.Close()
	}
	return s, nil
}

// readConf reads "key = value" lines, blank lines and # comments, each of keys once.
func readConf(path string, keys ...string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	conf := map[string]string{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || !slices.Contains(keys, key) {
			return nil, fmt.Errorf("line %d: not one of %s = value", n, strings.Join(keys, ", "))
		}
		if _, dup := conf[key]; dup {
			return nil, fmt.Errorf("line %d: %s given twice", n, key)
		}
		conf[key] = value
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for _, key := range keys {
		if conf[key] == "" {
			return nil, fmt.Errorf("%s is missing", key)
		}
	}
	return conf, nil
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// hash is user's stored hash, or sql.ErrNoRows.
func (s *SQL) hash(ctx context.Context, q querier, user string) (string, error) {
	rows, err := q.QueryContext(ctx, s.Select.text, s.Select.args(user, "")...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", sql.ErrNoRows
	}
	var hash string
	if err := rows.Scan(&hash); err != nil {
		return "", fmt.Errorf("select: %v", err)
	}
	if rows.Next() {
		return "", fmt.Errorf("select: more than one row for %s", user)
	}
	return prefixed(hash, s.DefaultScheme), rows.Err()
}

func (s *SQL) Verify(user, password string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sqlTimeout)
	defer cancel()
	hash, err := s.hash(ctx, s.DB, user)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return s.Hasher.Verify(hash, password)
}

// Change checks the current password and stores the new hash in one transaction; with
// SELECT ... FOR UPDATE, no other writer comes in between.
func (s *SQL) Change(user, current, next string) error {
	hash, err := verifiedHash(s.Hasher, next)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), sqlTimeout)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	old, err := s.hash(ctx, tx, user)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRefused
	} else if err != nil {
		return err
	}
	if ok, err := s.Hasher.Verify(old, current); err != nil {
		return err
	} else if !ok {
		return ErrRefused
	}
	res, err := tx.ExecContext(ctx, s.Update.text, s.Update.args(user, hash)...)
	if err != nil {
		return fmt.Errorf("update: %v", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return fmt.Errorf("update: %d rows would change, not 1; none did", n)
	}
	return tx.Commit()
}
