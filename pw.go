package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// pwTimeout bounds one pw run, which rewrites the password databases.
const pwTimeout = 20 * time.Second

// Pw changes FreeBSD system users' passwords with pw(8), after Dovecot's own passdb has taken
// the current one. pw hashes the new password as the user's login class says.
type Pw struct {
	Path string
	Auth DovecotAuth
}

func (p Pw) Verify(user, password string) (bool, error) {
	return p.Auth.Verify(user, password)
}

func (p Pw) Change(user, current, next string) error {
	if ok, err := p.Auth.Verify(user, current); err != nil {
		return err
	} else if !ok {
		return ErrRefused
	}
	ctx, cancel := context.WithTimeout(context.Background(), pwTimeout)
	defer cancel()
	// -h 0 reads the password from standard input, so it never shows on a command line.
	cmd := exec.CommandContext(ctx, p.Path, "usermod", "-n", user, "-h", "0")
	cmd.Stdin = strings.NewReader(next + "\n")
	cmd.Env = []string{}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s usermod: %w: %s", p.Path, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
