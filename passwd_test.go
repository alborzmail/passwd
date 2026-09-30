package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testHasher stands in for doveadm, which TestDoveadm checks on its own.
type testHasher struct{}

func (testHasher) Hash(password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	return "{TEST}" + hex.EncodeToString(sum[:]), nil
}

func (h testHasher) Verify(hash, password string) (bool, error) {
	want, _ := h.Hash(password)
	return hash == want, nil
}

func hashed(password string) string { h, _ := testHasher{}.Hash(password); return h }

// users holds the forms a passwd-file line takes: extra fields, none, an unprefixed hash,
// CRLF, a comment.
var users = "# users\n" +
	"alice@example.org:" + hashed("old-secret") + ":1000:1000::/home/alice::userdb_quota_rule=*:storage=1G\n" +
	"bob@example.org:" + hashed("bobs") + "\r\n" +
	"carol@example.org:" + strings.TrimPrefix(hashed("carols"), "{TEST}") + "\n"

func setup(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users")
	if err := os.WriteFile(path, []byte(users), 0o640); err != nil {
		t.Fatal(err)
	}
	return &Server{
		Backend:   &PasswdFile{Path: path, Hasher: testHasher{}, DefaultScheme: "TEST"},
		Limit:     NewLimiter(failedTries, failedWindow),
		MinLength: 8,
		Log:       log.New(io.Discard, "", 0),
	}, path
}

// converse sends lines as alborz does and returns every reply until the server hangs up.
func converse(t *testing.T, s *Server, lines ...string) []string {
	t.Helper()
	client, server := net.Pipe()
	go s.serve(server)
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		for _, l := range lines {
			fmt.Fprintf(client, "%s\r\n", l)
		}
	}()
	var replies []string
	sc := bufio.NewScanner(client)
	for sc.Scan() {
		replies = append(replies, strings.TrimRight(sc.Text(), "\r"))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return replies
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestChangeKeepsTheRestOfTheFile(t *testing.T) {
	for _, c := range []struct{ user, old, want string }{
		{"alice@example.org", "old-secret", hashed("old-secret")},
		{"bob@example.org", "bobs", hashed("bobs")},
		{"carol@example.org", "carols", strings.TrimPrefix(hashed("carols"), "{TEST}")},
	} {
		t.Run(c.user, func(t *testing.T) {
			s, path := setup(t)
			got := converse(t, s, "user "+c.user, "pass "+c.old, "newpass fresh secret", "quit")
			want := []string{"200 poppassd", "200 Your password please", "200 Your new password please", "200 Password changed", "200 Bye"}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("replies %q, want %q", got, want)
			}
			if after, want := read(t, path), strings.Replace(users, c.user+":"+c.want, c.user+":"+hashed("fresh secret"), 1); after != want {
				t.Fatalf("the file reads\n%s\nwant\n%s", after, want)
			}
			if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
				t.Errorf("mode %v, want 0640", info.Mode().Perm())
			}
		})
	}
}

func TestRefusalsChangeNothing(t *testing.T) {
	for _, c := range []struct {
		name  string
		lines []string
		last  string
	}{
		{"wrong password", []string{"user alice@example.org", "pass wrong", "newpass fresh-secret"}, "500 Old password is incorrect"},
		{"unknown user", []string{"user nobody@example.org", "pass wrong", "newpass fresh-secret"}, "500 Old password is incorrect"},
		{"short", []string{"user alice@example.org", "pass old-secret", "newpass short"}, "500 The new password is shorter than 8 characters"},
		{"out of order", []string{"pass old-secret"}, "500 user expected"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, path := setup(t)
			got := converse(t, s, c.lines...)
			if len(got) == 0 || got[len(got)-1] != c.last {
				t.Fatalf("replies %q, want the last %q", got, c.last)
			}
			if read(t, path) != users {
				t.Fatal("a refusal changed the file")
			}
		})
	}
}

func TestPausedAfterFailedTries(t *testing.T) {
	s, _ := setup(t)
	for range failedTries {
		converse(t, s, "user ALICE@example.org", "pass wrong")
	}
	got := converse(t, s, "user alice@example.org", "pass old-secret", "newpass fresh-secret")
	if last := got[len(got)-1]; last != "500 Too many failed attempts, try again later" {
		t.Fatalf("the right password after %d failures: %q", failedTries, got)
	}
}

// TestDoveadm runs against a real doveadm named by $DOVEADM, such as in the dovecot/dovecot image.
func TestDoveadm(t *testing.T) {
	path := os.Getenv("DOVEADM")
	if path == "" {
		t.Skip("$DOVEADM names no doveadm")
	}
	d := Doveadm{Path: path, Scheme: "SHA512-CRYPT"}
	if err := d.Check(); err != nil {
		t.Fatal(err)
	}
	if err := (Doveadm{Path: path, Scheme: "PLAIN"}).Check(); err == nil {
		t.Fatal("a plaintext scheme was taken")
	}
	hash, err := d.Hash("a pass:word")
	if err != nil {
		t.Fatal(err)
	}
	for password, want := range map[string]bool{"a pass:word": true, "a pass:wore": false} {
		if got, err := d.Verify(hash, password); err != nil || got != want {
			t.Errorf("Verify(%q) = %v, %v; want %v", password, got, err, want)
		}
	}
	if _, err := d.Verify("no-scheme", "x"); err == nil {
		t.Error("a hash without a scheme verified without an error")
	}
}
