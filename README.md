# alborz-passwd

Changes Dovecot passwords over the poppassd protocol (USER, PASS,
NEWPASS, QUIT), for [alborz](https://github.com/alborzmail) or any other
poppassd client on the mail host. The web application never touches the
user database; this small service does, with least privilege.

Backends: a Dovecot passwd-file (`-passwd-file`), the database of
Dovecot's SQL passdb (`-sql`), or FreeBSD's system users (`-pw`). LDAP,
OpenBSD and NetBSD are not supported.

## How it works

- For a passwd-file and SQL, `doveadm pw -t` verifies the current
  password against the stored hash, and `doveadm pw -s` hashes the new one, which is verified again
  before it is stored. Every scheme Dovecot knows is handled by Dovecot's
  own code; passwords reach doveadm on standard input, never the command
  line. Plaintext schemes are refused.
- A wrong password and an unknown user get the same answer, after three
  seconds. Five failures within ten minutes pause the user (fail2ban's
  defaults); the count is in memory and a restart clears it.
- At most 16 conversations at once, each bounded to 30 seconds.

### passwd-file

- The file is replaced atomically: the new content goes to a file beside
  it, with the old file's mode, owner and group, and is renamed over it.
  Only the password field of the one user changes. Writers are serialised
  by `flock` on `<file>.lock`; administrators' scripts can take it with
  `flock(1)`.
- The current password is checked again under the lock, so a change
  made in between is not overwritten.

### SQL

`-sql /etc/dovecot/passwd.sql` names a file, readable by the service
only, since it holds the database password:

    # pgsql (PostgreSQL), mysql (MySQL, MariaDB) or sqlite
    driver = pgsql
    dsn = host=/run/postgresql dbname=mail user=passwd
    select = SELECT password FROM users WHERE userid = %n AND domain = %d FOR UPDATE
    update = UPDATE users SET password = %p WHERE userid = %n AND domain = %d

- `select` returns one row: none is an unknown user, two are an error.
  The hash is the column named `password`, as in Dovecot's
  `password_query`, and other columns are ignored. A hash without a
  `{SCHEME}` prefix takes `-default-scheme`, and one in a column named
  `password_noscheme` always does.
- The variables are bound as parameters, never pasted into the SQL, so
  they stand unquoted: `%u` the user as alborz sends it
  (`%{user}` in Dovecot 2.4), `%n` its local part (`%{user|username}`),
  `%d` its domain (`%{user|domain}`), and `%p`, in `update` only, the new
  hash with its `{SCHEME}` prefix. No other `%` is taken.
- The select, the check of the current password and the update run in
  one transaction; an update changing anything but one row is rolled
  back. `FOR UPDATE` keeps another writer out in between on PostgreSQL
  and MySQL; on SQLite, add `_txlock=immediate` to the DSN
  (`file:/var/lib/dovecot/users.db?_txlock=immediate`).
- The DSN is the Go driver's: [pgx](https://github.com/jackc/pgx)
  takes libpq's `key=value` and URLs, so Dovecot's `connect` line for
  pgsql works as it is;
  [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql#dsn-data-source-name)
  takes `user:password@unix(/run/mysqld/mysqld.sock)/mail`;
  [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) a path or
  `file:` URI.
- Each driver is built in only on request, with its name as the build
  tag: `go build -tags pgsql .`. Without a tag the binary has no
  dependency beyond Go's standard library.

### FreeBSD system users

With `-pw /usr/sbin/pw`, Dovecot's auth service verifies the current
password over its auth-client socket (`-auth-socket`, default
`/var/run/dovecot/auth-client`), through whatever passdb Dovecot signs
in with, PAM usually; `-auth-service` (default `imap`) is the protocol
the passdb sees. `pw usermod -n <user> -h 0` then sets the new one, read
from standard input and hashed as the user's login class says. Neither
password nor hash appears on a command line, and no setuid helper runs.

- pw needs root, so the service runs as root. Listen on a Unix socket in
  a directory of alborz's group (`-listen unix:/var/run/alborz-passwd/sock`,
  the directory `root:alborz 0750`) with umask 007: a new socket takes
  its directory's group.
- alborz sends the local part (`?user=local`), as PAM names the users.
- Any account Dovecot's passdb takes can be changed, root's too where
  PAM lets root sign in to Dovecot; deny such accounts in the passdb.
- The current password is checked again just before pw runs, but pw
  has its own lock and a change made in between is overwritten.
- Only the local password database changes; a PAM stack that
  authenticates elsewhere (LDAP, Kerberos) is not written.
- OpenBSD's and NetBSD's tools (`usermod -p`, `chpass -a`) take the new
  hash as an argument, which other local users can read in `ps`, so
  they are not supported.

## Install

    go build -o /usr/local/sbin/alborz-passwd .   # -tags pgsql, mysql or sqlite for -sql
    useradd --system --no-create-home --gid dovecot alborz-passwd
    groupadd --system alborz          # the group alborz runs in
    install -d -o alborz-passwd -g dovecot -m 0750 /etc/dovecot/passwd.d
    mv /etc/dovecot/users /etc/dovecot/passwd.d/users   # root:dovecot 0640
    cp systemd/alborz-passwd.* /etc/systemd/system/
    systemctl enable --now alborz-passwd.socket

Point Dovecot's passdb and userdb at the moved file, and alborz at the
socket:

    alborz example.org example.org=poppassd+unix:///run/alborz-passwd.sock

The unit serves a passwd-file. For `-sql`, give the unit `-sql` in
`ExecStart`; the file's directory and `CAP_CHOWN` are then not needed,
and a database reached over TCP needs `PrivateNetwork`,
`RestrictAddressFamilies` and `IPAddressDeny` loosened.

Flags: `-passwd-file`, `-sql` or `-pw` (one is required), `-scheme`
(new hashes, default `SHA512-CRYPT`), `-default-scheme` (for hashes
without a `{SCHEME}` prefix, default `CRYPT`), `-min-length` (default
8), `-doveadm`, `-auth-socket` and `-auth-service` (for `-pw`),
`-listen` (`unix:/path` or a loopback `host:port`; unset takes the
socket systemd passes).

## Security notes

- The protocol is plain text, so the service listens only on a Unix
  socket or a loopback address (127.0.0.0/8, ::1) and refuses to start
  on any other. The socket unit lets only the `alborz` group connect; a
  loopback port is open to every local user.
- `doveadm pw -t` takes the stored hash as an argument. The unit hides
  the service's processes from other users (`ProtectProc=invisible`).
- A passwd-file service needs to write the file's directory and
  `CAP_CHOWN` to keep the file's owner; the unit grants nothing else.
- With Dovecot's `auth_cache_size` set, the old password keeps working
  until its cache entry expires: flush it with
  `doveadm auth cache flush <user>` or leave the cache off.
- No password reset: proving who someone is without the password is not
  this service's job.

## Test

    go test ./...
    # Dovecot's auth service, in the dovecot/dovecot image (static passdb):
    GOOS=linux go test -c -o passwd.test . && docker run -d --name dc \
        -e USER_PASSWORD=secret dovecot/dovecot:2.4.5 && docker cp passwd.test dc:/t &&
      docker exec -e AUTH_SOCKET=/run/dovecot/auth-client -e AUTH_USER=alice \
        -e AUTH_PASSWORD=secret dc /t -test.v -test.run DovecotAuth
    # SQL: SQLite in process, PostgreSQL and MySQL where a DSN is given:
    PGSQL_DSN=postgres://... MYSQL_DSN='user:pw@tcp(127.0.0.1:3306)/db' \
      go test -tags pgsql,mysql,sqlite ./...
    # doveadm against a real Dovecot:
    GOOS=linux go test -c -o passwd.test . &&
      docker run --rm -v $PWD/passwd.test:/t:ro -e DOVEADM=/dovecot/bin/doveadm \
        --entrypoint /t dovecot/dovecot:2.4.5 -test.v

## License

MIT
