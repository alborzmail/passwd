// Command alborz-passwd changes Dovecot passwords over the poppassd protocol, for alborz or any
// other poppassd client on the mail host.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
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
		listen  string
		file    PasswdFile
		sqlConf string
		pw      Pw
		dove    Doveadm
		minLen  int
	)
	fs.StringVar(&listen, "listen", "",
		"unix:/path or a loopback host:port to listen on; unset takes the socket systemd passes")
	fs.StringVar(&file.Path, "passwd-file", "", "the Dovecot passwd-file whose passwords change")
	fs.StringVar(&sqlConf, "sql", "", "the file naming the SQL database and its queries")
	fs.StringVar(&pw.Path, "pw", "", "FreeBSD's pw(8), to change system users' passwords")
	// Dovecot's base_dir defaults to /var/run/dovecot.
	fs.StringVar(&pw.Auth.Socket, "auth-socket", "/var/run/dovecot/auth-client",
		"Dovecot's auth-client socket, which verifies the current password for -pw")
	fs.StringVar(&pw.Auth.Service, "auth-service", "imap",
		"the protocol Dovecot's passdb sees the -pw verification come from")
	fs.StringVar(&file.DefaultScheme, "default-scheme", "CRYPT",
		"the passdb's default_password_scheme, for a stored password without a {SCHEME} prefix")
	fs.StringVar(&dove.Path, "doveadm", "doveadm", "the doveadm that verifies and makes hashes")
	fs.StringVar(&dove.Scheme, "scheme", "SHA512-CRYPT", "the scheme a new password is hashed with")
	fs.IntVar(&minLen, "min-length", 8, "the fewest characters a new password may have")
	if err := fs.Parse(args); err != nil {
		return err
	}
	given := 0
	for _, f := range []string{file.Path, sqlConf, pw.Path} {
		if f != "" {
			given++
		}
	}
	if given != 1 {
		return errors.New("give one of -passwd-file, -sql and -pw")
	}
	if pw.Path == "" {
		if err := dove.Check(); err != nil {
			return err
		}
	}
	var (
		backend Backend
		what    string
	)
	switch {
	case file.Path != "":
		// The file is replaced, not written, so a symlink would be replaced by a file.
		real, err := filepath.EvalSymlinks(file.Path)
		if err != nil {
			return err
		}
		file.Path = real
		if _, err := os.ReadFile(file.Path); err != nil {
			return err
		}
		file.Hasher = dove
		backend, what = &file, file.Path
	case sqlConf != "":
		db, err := OpenSQL(sqlConf, dove, dove.Scheme, file.DefaultScheme)
		if err != nil {
			return fmt.Errorf("%s: %v", sqlConf, err)
		}
		backend, what = db, sqlConf
	default:
		if _, err := exec.LookPath(pw.Path); err != nil {
			return err
		}
		if err := pw.Auth.Check(); err != nil {
			return err
		}
		backend, what = pw, "system users"
	}

	ln, err := listener(listen)
	if err != nil {
		return err
	}
	if err := loopback(ln.Addr()); err != nil {
		ln.Close()
		return err
	}
	logger.Printf("alborz-passwd: serving %s on %s", what, ln.Addr())
	s := &Server{Backend: backend, Limit: NewLimiter(failedTries, failedWindow), MinLength: minLen,
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

// loopback refuses an address beyond this host: poppassd carries passwords in plain text.
func loopback(addr net.Addr) error {
	if addr.Network() == "unix" {
		return nil
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return err
	}
	if !ap.Addr().Unmap().IsLoopback() {
		return fmt.Errorf("%s is not a Unix socket or a loopback address: poppassd is plain text", addr)
	}
	return nil
}
