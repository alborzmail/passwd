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

// A Query is SQL with Dovecot's variables bound as parameters. A quoted literal holding
// variables, as Dovecot's queries quote them, is bound whole: '%n@%d' is one parameter.
type Query struct {
	text   string
	params [][]part
}

// A part of a parameter is text, or a variable (user, or hash, the new password's) through
// its filters.
type part struct {
	text    string
	name    string
	filters []string
}

// short are Dovecot 2.3's variables in 2.4's syntax.
var short = map[byte]string{'u': "user", 'n': "user|username", 'd': "user|domain", 'p': "hash"}

// long are the names %{...} takes: 2.4's user, 2.3's username and domain, and hash.
var long = map[string]string{"user": "user", "username": "user|username", "domain": "user|domain",
	"hash": "hash"}

// modifiers are Dovecot 2.3's, as in %Lu.
var modifiers = map[byte]string{'L': "|lower", 'U': "|upper"}

// filters are Dovecot 2.4's, each with the variable it takes.
var filters = map[string]struct {
	of string
	fn func(string) string
}{
	"username": {"user", func(s string) string { name, _, _ := strings.Cut(s, "@"); return name }},
	"domain":   {"user", func(s string) string { _, domain, _ := strings.Cut(s, "@"); return domain }},
	"lower":    {"user", strings.ToLower},
	"upper":    {"user", strings.ToUpper},
}

func ParseQuery(query string, bind func(i int) string) (Query, error) {
	var q Query
	var b strings.Builder
	for i := 0; i < len(query); {
		var parts []part
		n := 1
		var err error
		switch c := query[i]; {
		case c == '\'' || c == '"':
			if n, err = quoted(query[i:]); err == nil && strings.Contains(query[i:i+n], "%") {
				parts, err = template(strings.ReplaceAll(query[i+1:i+n-1], string(c)+string(c), string(c)))
			}
		case c == '%':
			var p part
			p, n, err = variable(query[i:])
			parts = []part{p}
		}
		switch {
		case err != nil:
			return Query{}, fmt.Errorf("%q: %v", query, err)
		case parts == nil:
			b.WriteString(query[i : i+n])
		case len(parts) == 1 && parts[0].name == "":
			b.WriteString(parts[0].text)
		default:
			q.params = append(q.params, parts)
			b.WriteString(bind(len(q.params)))
		}
		i += n
	}
	q.text = b.String()
	return q, nil
}

// quoted is the length of the literal s starts with, whose quote a doubled one escapes.
func quoted(s string) (int, error) {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			continue
		}
		if i+1 < len(s) && s[i+1] == s[0] {
			i++
			continue
		}
		return i + 1, nil
	}
	return 0, errors.New("a quote is not closed")
}

func template(s string) ([]part, error) {
	var parts []part
	for len(s) > 0 {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			return append(parts, part{text: s}), nil
		}
		p, n, err := variable(s[i:])
		if err != nil {
			return nil, err
		}
		parts = append(parts, part{text: s[:i]}, p)
		s = s[i+n:]
	}
	return parts, nil
}

// variable reads the one s starts with, in 2.3's or 2.4's syntax, and its length; %% is text.
func variable(s string) (part, int, error) {
	switch {
	case strings.HasPrefix(s, "%%"):
		return part{text: "%"}, 2, nil
	case strings.HasPrefix(s, "%{"):
		end := strings.IndexByte(s, '}')
		if end < 0 {
			return part{}, 0, fmt.Errorf("%s: no closing }", s)
		}
		p, err := expand(s[2:end])
		return p, end + 1, err
	case len(s) > 2 && modifiers[s[1]] != "" && short[s[2]] != "":
		p, err := expand(short[s[2]] + modifiers[s[1]])
		return p, 3, err
	case len(s) > 1 && short[s[1]] != "":
		p, err := expand(short[s[1]])
		return p, 2, err
	}
	return part{}, 0, fmt.Errorf("%.3s: the variables are %%u, %%n, %%d, %%p and %%{user|filter}", s)
}

// expand reads a name and its filters, as in user | username | lower.
func expand(expr string) (part, error) {
	name, rest, _ := strings.Cut(expr, "|")
	full, ok := long[strings.TrimSpace(name)]
	if !ok {
		return part{}, fmt.Errorf("%%{%s}: no variable %q", expr, strings.TrimSpace(name))
	}
	fs := strings.Split(full, "|")
	if rest != "" {
		fs = append(fs, strings.Split(rest, "|")...)
	}
	p := part{name: fs[0]}
	for _, f := range fs[1:] {
		f = strings.TrimSpace(f)
		if filters[f].of != p.name {
			return part{}, fmt.Errorf("%%{%s}: %s takes no filter %q", expr, p.name, f)
		}
		p.filters = append(p.filters, f)
	}
	return p, nil
}

func (q Query) args(user, hash string) []any {
	values := map[string]string{"user": user, "hash": hash}
	args := make([]any, len(q.params))
	for i, parts := range q.params {
		var b strings.Builder
		for _, p := range parts {
			v := p.text
			if p.name != "" {
				v = values[p.name]
			}
			for _, f := range p.filters {
				v = filters[f].fn(v)
			}
			b.WriteString(v)
		}
		args[i] = b.String()
	}
	return args
}

func (q Query) uses(name string) bool {
	return slices.ContainsFunc(q.params, func(parts []part) bool {
		return slices.ContainsFunc(parts, func(p part) bool { return p.name == name })
	})
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
	if !s.Select.uses("user") || s.Select.uses("hash") {
		return nil, errors.New("select: name the user, as %u or %{user}, and not the hash")
	}
	if !s.Update.uses("user") || !s.Update.uses("hash") {
		return nil, errors.New("update: name the user, as %u or %{user}, and the hash, as %p")
	}
	if !slices.Contains(sql.Drivers(), driver.name) {
		return nil, fmt.Errorf("driver %q is not built in: build with -tags %s", conf["driver"], conf["driver"])
	}
	if s.DB, err = sql.Open(driver.name, conf["dsn"]); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), sqlTimeout)
	defer cancel()
	// Running the select and preparing the update find a misspelt table or column, and a
	// select without the password among its columns, before the first reader does.
	if err := s.check(ctx); err != nil {
		s.DB.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQL) check(ctx context.Context) error {
	rows, err := s.DB.QueryContext(ctx, s.Select.text, s.Select.args("", "")...)
	if err != nil {
		return fmt.Errorf("select: %v", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("select: %v", err)
	}
	if _, _, err := passwordColumn(cols); err != nil {
		return err
	}
	stmt, err := s.DB.PrepareContext(ctx, s.Update.text)
	if err != nil {
		return fmt.Errorf("update: %v", err)
	}
	return stmt.Close()
}

// passwordColumn finds the hash among the select's columns by Dovecot's names: password, or
// password_noscheme, whose value never carries a {SCHEME} prefix.
func passwordColumn(cols []string) (i int, noscheme bool, err error) {
	i = -1
	for j, c := range cols {
		if c != "password" && c != "password_noscheme" {
			continue
		}
		if i >= 0 {
			return 0, false, fmt.Errorf("select: both %s and %s", cols[i], c)
		}
		i, noscheme = j, c == "password_noscheme"
	}
	if i >= 0 {
		return i, noscheme, nil
	}
	return 0, false, fmt.Errorf("select: none of the columns %s is password or password_noscheme",
		strings.Join(cols, ", "))
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
	cols, err := rows.Columns()
	if err != nil {
		return "", err
	}
	i, noscheme, err := passwordColumn(cols)
	if err != nil {
		return "", err
	}
	// Dovecot takes the other columns as extra fields; here they are read and left.
	dest := make([]any, len(cols))
	for j := range dest {
		dest[j] = new(any)
	}
	var hash string
	dest[i] = &hash
	if err := rows.Scan(dest...); err != nil {
		return "", fmt.Errorf("select: %v", err)
	}
	if rows.Next() {
		return "", fmt.Errorf("select: more than one row for %s", user)
	}
	if noscheme {
		return "{" + s.DefaultScheme + "}" + hash, rows.Err()
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
