package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// PasswdFile is a Dovecot passwd-file: one user:password[:uid:gid:gecos:home:shell:extra]
// line per user. Only the password field of the user changing it is ever written; every other
// byte is kept.
type PasswdFile struct {
	Path   string
	Hasher Hasher
	// DefaultScheme is the passdb's, for a password written without a {SCHEME} prefix.
	DefaultScheme string

	mu sync.Mutex
}

// field finds user's line and returns the file with the password field's offsets in it, or -1.
func field(data []byte, user string) (start, end int) {
	for off := 0; off < len(data); {
		line := data[off:]
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line = line[:i]
		}
		name, rest, ok := bytes.Cut(line, []byte(":"))
		if ok && string(name) == user {
			start = off + len(name) + 1
			if i := bytes.IndexByte(rest, ':'); i >= 0 {
				return start, start + i
			}
			return start, start + len(bytes.TrimRight(rest, "\r"))
		}
		off += len(line) + 1
	}
	return -1, -1
}

// prefixed gives a stored hash without a {SCHEME} prefix the passdb's default scheme.
func prefixed(hash, scheme string) string {
	if strings.HasPrefix(hash, "{") {
		return hash
	}
	return "{" + scheme + "}" + hash
}

func (f *PasswdFile) Verify(user, password string) (bool, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return false, err
	}
	start, end := field(data, user)
	if start < 0 {
		return false, nil
	}
	return f.Hasher.Verify(prefixed(string(data[start:end]), f.DefaultScheme), password)
}

func (f *PasswdFile) Change(user, current, next string) error {
	hash, err := verifiedHash(f.Hasher, next)
	if err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	unlock, err := lock(f.Path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()

	data, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}
	start, end := field(data, user)
	if start < 0 {
		return ErrRefused
	}
	// The file may have changed since PASS was answered.
	if ok, err := f.Hasher.Verify(prefixed(string(data[start:end]), f.DefaultScheme), current); err != nil {
		return err
	} else if !ok {
		return ErrRefused
	}
	changed := append(append(append([]byte{}, data[:start]...), hash...), data[end:]...)
	return replace(f.Path, changed)
}

// lock takes an exclusive lock on path, which administrators' scripts can take too
// (flock(1)); the file itself is replaced, so it cannot carry the lock.
func lock(path string) (func(), error) {
	l, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(l.Fd()), syscall.LOCK_EX); err != nil {
		l.Close()
		return nil, err
	}
	return func() { l.Close() }, nil
}

// replace writes data to path through a file beside it renamed over it, with path's mode,
// owner and group, so a reader sees the old file or the new one and never a part.
func replace(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no owner in the file's status")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	made, err := tmp.Stat()
	if err != nil {
		return err
	}
	// Giving it another owner takes CAP_CHOWN; the same owner takes nothing.
	if mine := made.Sys().(*syscall.Stat_t); mine.Uid != stat.Uid || mine.Gid != stat.Gid {
		if err := tmp.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
