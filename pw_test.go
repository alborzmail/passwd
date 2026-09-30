package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAuth answers Dovecot's auth protocol on a Unix socket, taking the passwords given, and
// failing temporarily for the user "temp".
func fakeAuth(t *testing.T, passwords map[string]string) string {
	t.Helper()
	// t.TempDir is too long a path for a socket on macOS.
	dir, err := os.MkdirTemp("", "auth")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "auth-client")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.WriteString(conn, "VERSION\t1\t3\nMECH\tPLAIN\tplaintext\nMECH\tLOGIN\tplaintext\nSPID\t1\nCUID\t1\nCOOKIE\tc\nDONE\n")
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					f := strings.Split(sc.Text(), "\t")
					if f[0] != "AUTH" {
						continue
					}
					var resp []byte
					for _, p := range f {
						if v, ok := strings.CutPrefix(p, "resp="); ok {
							resp, _ = base64.StdEncoding.DecodeString(v)
						}
					}
					parts := strings.Split(string(resp), "\x00")
					switch user := parts[1]; {
					case user == "temp":
						fmt.Fprintf(conn, "FAIL\t%s\tuser=%s\ttemp\n", f[1], user)
					case passwords[user] == parts[2]:
						fmt.Fprintf(conn, "OK\t%s\tuser=%s\n", f[1], user)
					default:
						fmt.Fprintf(conn, "FAIL\t%s\tuser=%s\n", f[1], user)
					}
				}
			}()
		}
	}()
	return socket
}

// fakePw writes a pw that records its arguments and standard input beside itself, and exits
// with status.
func fakePw(t *testing.T, status int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pw")
	script := fmt.Sprintf("#!/bin/sh\necho \"$*\" > \"$0.args\"\nIFS= read -r line; echo \"$line\" > \"$0.stdin\"\nexit %d\n", status)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func setupPw(t *testing.T, status int) (*Server, string) {
	t.Helper()
	pw := Pw{Path: fakePw(t, status), Auth: DovecotAuth{
		Socket: fakeAuth(t, map[string]string{"alice": "old-secret"}), Service: "imap"}}
	if err := pw.Auth.Check(); err != nil {
		t.Fatal(err)
	}
	return &Server{Backend: pw, Limit: NewLimiter(failedTries, failedWindow), MinLength: 8,
		Log: log.New(io.Discard, "", 0)}, pw.Path
}

func TestPwChange(t *testing.T) {
	s, pw := setupPw(t, 0)
	got := converse(t, s, "user alice", "pass old-secret", "newpass fresh secret", "quit")
	if got[len(got)-1] != "200 Bye" {
		t.Fatalf("replies %q", got)
	}
	if args := read(t, pw+".args"); args != "usermod -n alice -h 0\n" {
		t.Errorf("pw ran with %q", args)
	}
	if stdin := read(t, pw+".stdin"); stdin != "fresh secret\n" {
		t.Errorf("pw read %q", stdin)
	}
}

func TestPwRefusals(t *testing.T) {
	for _, c := range []struct {
		name, user, pass string
		status           int
		last             string
		ran              bool
	}{
		{"wrong password", "alice", "wrong", 0, "500 Old password is incorrect", false},
		{"unknown user", "bob", "old-secret", 0, "500 Old password is incorrect", false},
		{"auth failing", "temp", "old-secret", 0, "500 Server error", false},
		{"pw failing", "alice", "old-secret", 1, "500 Server error, password not changed", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, pw := setupPw(t, c.status)
			got := converse(t, s, "user "+c.user, "pass "+c.pass, "newpass fresh secret")
			if got[len(got)-1] != c.last {
				t.Errorf("replies %q, want the last %q", got, c.last)
			}
			if _, err := os.Stat(pw + ".args"); (err == nil) != c.ran {
				t.Errorf("pw ran: %v, want %v", err == nil, c.ran)
			}
		})
	}
}
