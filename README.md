# alborz-passwd

Changes Dovecot passwords over the poppassd protocol (USER, PASS,
NEWPASS, QUIT), for [alborz](https://github.com/alborzmail) or any other
poppassd client on the mail host. The web application never touches the
user database; this small service does, with least privilege.

Backend: a Dovecot passwd-file. SQL and LDAP may follow.

## How it works

- `doveadm pw -t` verifies the current password against the user's line,
  and `doveadm pw -s` hashes the new one, which is verified again before
  it is written. Every scheme Dovecot knows is handled by Dovecot's own
  code; passwords reach doveadm on standard input, never the command
  line. Plaintext schemes are refused.
- The file is replaced atomically: the new content goes to a file beside
  it, with the old file's mode, owner and group, and is renamed over it.
  Only the password field of the one user changes. Writers are serialised
  by `flock` on `<file>.lock`; administrators' scripts can take it with
  `flock(1)`.
- The current password is checked again under the lock, so a change
  made in between is not overwritten.
- A wrong password and an unknown user get the same answer, after three
  seconds. Five failures within ten minutes pause the user (fail2ban's
  defaults); the count is in memory and a restart clears it.
- At most 16 conversations at once, each bounded to 30 seconds.

## Install

    go build -o /usr/local/sbin/alborz-passwd .
    useradd --system --no-create-home --gid dovecot alborz-passwd
    groupadd --system alborz          # the group alborz runs in
    install -d -o alborz-passwd -g dovecot -m 0750 /etc/dovecot/passwd.d
    mv /etc/dovecot/users /etc/dovecot/passwd.d/users   # root:dovecot 0640
    cp systemd/alborz-passwd.* /etc/systemd/system/
    systemctl enable --now alborz-passwd.socket

Point Dovecot's passdb and userdb at the moved file, and alborz at the
socket:

    alborz example.org example.org=poppassd+unix:///run/alborz-passwd.sock

Flags: `-passwd-file` (required), `-scheme` (new hashes, default
`SHA512-CRYPT`), `-default-scheme` (for hashes without a `{SCHEME}`
prefix, default `CRYPT`), `-min-length` (default 8), `-doveadm`,
`-listen` (`unix:/path` or `host:port`; unset takes the socket systemd
passes).

## Security notes

- The protocol is plain text. The socket unit lets only the `alborz`
  group connect; do not expose a TCP port beyond loopback.
- `doveadm pw -t` takes the stored hash as an argument. The unit hides
  the service's processes from other users (`ProtectProc=invisible`).
- The service needs to write the passwd-file's directory and
  `CAP_CHOWN` to keep the file's owner; the unit grants nothing else.
- With Dovecot's `auth_cache_size` set, the old password keeps working
  until its cache entry expires: flush it with
  `doveadm auth cache flush <user>` or leave the cache off.
- No password reset: proving who someone is without the password is not
  this service's job.

## Test

    go test ./...
    # doveadm against a real Dovecot:
    GOOS=linux go test -c -o passwd.test . &&
      docker run --rm -v $PWD/passwd.test:/t:ro -e DOVEADM=/dovecot/bin/doveadm \
        --entrypoint /t dovecot/dovecot:2.4.5 -test.v

## License

MIT
