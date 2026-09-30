package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"
)

// authTimeout bounds one question to Dovecot's auth service, its auth_failure_delay included.
const authTimeout = 10 * time.Second

// DovecotAuth asks Dovecot's auth service, over its auth-client socket, whether a password is
// a user's: the passdb Dovecot signs in with decides, PAM or BSD auth among them. No password
// or hash appears on a command line.
type DovecotAuth struct {
	Socket string
	// Service is the protocol the passdb sees, as its protocols and PAM service may depend on it.
	Service string
}

// dial connects and shakes hands (Dovecot's auth protocol 1): the server offers PLAIN.
func (a DovecotAuth) dial() (net.Conn, *bufio.Reader, error) {
	conn, err := net.DialTimeout("unix", a.Socket, authTimeout)
	if err != nil {
		return nil, nil, err
	}
	conn.SetDeadline(time.Now().Add(authTimeout))
	if _, err := fmt.Fprintf(conn, "VERSION\t1\t2\nCPID\t%d\n", os.Getpid()); err != nil {
		conn.Close()
		return nil, nil, err
	}
	r := bufio.NewReader(conn)
	plain := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("%s: %v", a.Socket, err)
		}
		f := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
		switch {
		case f[0] == "VERSION" && (len(f) < 2 || f[1] != "1"):
			conn.Close()
			return nil, nil, fmt.Errorf("%s: auth protocol %q", a.Socket, line)
		case f[0] == "MECH" && len(f) > 1 && f[1] == "PLAIN":
			plain = true
		case f[0] == "DONE":
			if !plain {
				conn.Close()
				return nil, nil, fmt.Errorf("%s offers no PLAIN mechanism", a.Socket)
			}
			return conn, r, nil
		}
	}
}

// Check connects once, so a wrong socket stops the service at startup.
func (a DovecotAuth) Check() error {
	conn, _, err := a.dial()
	if err != nil {
		return err
	}
	return conn.Close()
}

func (a DovecotAuth) Verify(user, password string) (bool, error) {
	conn, r, err := a.dial()
	if err != nil {
		return false, err
	}
	defer conn.Close()
	resp := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + password))
	// secured: the socket is local, so Dovecot takes a plaintext mechanism over it.
	if _, err := fmt.Fprintf(conn, "AUTH\t1\tPLAIN\tservice=%s\tsecured\tresp=%s\n", a.Service, resp); err != nil {
		return false, err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("%s: %v", a.Socket, err)
	}
	f := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
	switch {
	case len(f) >= 2 && f[0] == "OK" && f[1] == "1":
		return true, nil
	case len(f) >= 2 && f[0] == "FAIL" && f[1] == "1" && !slices.Contains(f[2:], "temp"):
		return false, nil
	}
	return false, fmt.Errorf("%s answered %q", a.Socket, strings.TrimSpace(line))
}
