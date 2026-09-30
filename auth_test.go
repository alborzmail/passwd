package main

import (
	"os"
	"testing"
)

// TestDovecotAuth asks a real Dovecot, on the socket $AUTH_SOCKET names, whose passdb takes
// $AUTH_PASSWORD for $AUTH_USER, as the dovecot/dovecot image's static passdb does.
func TestDovecotAuth(t *testing.T) {
	socket := os.Getenv("AUTH_SOCKET")
	if socket == "" {
		t.Skip("$AUTH_SOCKET names no Dovecot auth-client socket")
	}
	a := DovecotAuth{Socket: socket, Service: "imap"}
	if err := a.Check(); err != nil {
		t.Fatal(err)
	}
	user, password := os.Getenv("AUTH_USER"), os.Getenv("AUTH_PASSWORD")
	for try, want := range map[string]bool{password: true, password + "x": false} {
		if got, err := a.Verify(user, try); err != nil || got != want {
			t.Errorf("Verify(%q) = %v, %v; want %v", try, got, err, want)
		}
	}
}
