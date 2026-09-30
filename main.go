// Command alborz-passwd changes Dovecot passwords over the poppassd protocol, for alborz or any
// other poppassd client on the mail host.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Failed attempts per user within a window before a pause: fail2ban's maxretry and findtime.
const (
	failedTries  = 5
	failedWindow = 10 * time.Minute
)

// sessions bounds the conversations at once; each refusal holds one for refusalDelay.
const sessions = 16

func main() {
	logger := log.New(os.Stderr, "", 0)
	if err := run(os.Args[1:], logger); err != nil {
		logger.Fatalf("alborz-passwd: %v", err)
	}
}

func run(args []string, logger *log.Logger) error {
	fs := flag.NewFlagSet("alborz-passwd", flag.ContinueOnError)
	var (
		listen string
		file   PasswdFile
		dove   Doveadm
		minLen int
	)
	fs.StringVar(&listen, "listen", "",
		"unix:/path or host:port to listen on; unset takes the socket systemd passes")
	fs.StringVar(&file.Path, "passwd-file", "", "the Dovecot passwd-file whose passwords change; required")
	fs.StringVar(&file.DefaultScheme, "default-scheme", "CRYPT",
		"the passdb's default_password_scheme, for a password in the file without a {SCHEME} prefix")
	fs.StringVar(&dove.Path, "doveadm", "doveadm", "the doveadm that verifies and makes hashes")
	fs.StringVar(&dove.Scheme, "scheme", "SHA512-CRYPT", "the scheme a new password is hashed with")
	fs.IntVar(&minLen, "min-length", 8, "the fewest characters a new password may have")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if file.Path == "" {
		return errors.New("-passwd-file is required")
	}
	// The file is replaced, not written, so a symlink would be replaced by a file.
	real, err := filepath.EvalSymlinks(file.Path)
	if err != nil {
		return err
	}
	file.Path = real
	if _, err := os.ReadFile(file.Path); err != nil {
		return err
	}
	if err := dove.Check(); err != nil {
		return err
	}
	file.Hasher = dove

	ln, err := listener(listen)
	if err != nil {
		return err
	}
	logger.Printf("alborz-passwd: serving %s on %s", file.Path, ln.Addr())
	s := &Server{Backend: &file, Limit: NewLimiter(failedTries, failedWindow), MinLength: minLen,
		Log: logger, delay: refusalDelay}
	return s.Serve(ln, sessions)
}

// listener is the address given, or the first socket systemd passed (sd_listen_fds(3)).
func listener(listen string) (net.Listener, error) {
	if listen != "" {
		if path, ok := strings.CutPrefix(listen, "unix:"); ok {
			return net.Listen("unix", path)
		}
		return net.Listen("tcp", listen)
	}
	pid, _ := strconv.Atoi(os.Getenv("LISTEN_PID"))
	fds, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if pid != os.Getpid() || fds < 1 {
		return nil, errors.New("no -listen and no socket from systemd")
	}
	// The first passed descriptor is 3 (SD_LISTEN_FDS_START).
	f := os.NewFile(3, "systemd socket")
	defer f.Close()
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("the socket systemd passed: %v", err)
	}
	return ln, nil
}
