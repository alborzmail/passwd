package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// doveadmTimeout bounds one run; ARGON2 at Dovecot's defaults takes well under a second.
const doveadmTimeout = 10 * time.Second

// A Hasher checks and makes password hashes in Dovecot's {SCHEME}hash form.
type Hasher interface {
	Verify(hash, password string) (bool, error)
	Hash(password string) (string, error)
}

// Doveadm asks `doveadm pw`, so every scheme Dovecot knows is verified by Dovecot's own code.
// The password goes on standard input, never on the command line.
type Doveadm struct {
	Path   string
	Scheme string
}

// plaintext are the schemes that would keep the password itself.
var plaintext = []string{"PLAIN", "CLEAR", "CLEARTEXT", "PLAIN-TRUNC"}

// Check refuses a scheme that keeps the password or that this doveadm does not offer.
func (d Doveadm) Check() error {
	if slices.Contains(plaintext, d.Scheme) {
		return fmt.Errorf("scheme %s keeps the password in the file", d.Scheme)
	}
	out, err := d.run("", "pw", "-l")
	if err != nil {
		return err
	}
	if !slices.Contains(strings.Fields(out), d.Scheme) {
		return fmt.Errorf("%s pw -l does not list %s: %s", d.Path, d.Scheme, out)
	}
	return nil
}

func (d Doveadm) Verify(hash, password string) (bool, error) {
	_, err := d.run(password+"\n", "pw", "-t", hash)
	var exit *exec.ExitError
	// doveadm says "Password mismatch" and nothing more specific by its exit status.
	if errors.As(err, &exit) && strings.Contains(strings.ToLower(err.Error()), "mismatch") {
		return false, nil
	}
	return err == nil, err
}

func (d Doveadm) Hash(password string) (string, error) {
	// doveadm hashes an empty line when it is given one.
	if password == "" {
		return "", errors.New("doveadm: an empty password")
	}
	out, err := d.run(password+"\n"+password+"\n", "pw", "-s", d.Scheme)
	if err != nil {
		return "", err
	}
	hash := strings.TrimSpace(out)
	if !strings.HasPrefix(hash, "{"+d.Scheme+"}") || strings.ContainsAny(hash, ": \t\r\n") {
		return "", fmt.Errorf("doveadm pw -s %s answered %q", d.Scheme, hash)
	}
	return hash, nil
}

// run starts doveadm without its configuration (-O), which pw does not need and the service
// may not read.
func (d Doveadm) run(stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), doveadmTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.Path, append([]string{"-O"}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = []string{}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", d.Path, args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
