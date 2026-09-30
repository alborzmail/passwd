# alborz-passwd

Changes Dovecot passwords over the poppassd protocol (USER, PASS,
NEWPASS, QUIT) for [alborz](https://github.com/alborzmail) or any other
poppassd client on the mail host, so the web application never writes
the user database.

Backends: a Dovecot passwd-file (`-passwd-file`), the database of
Dovecot's SQL passdb (`-sql`), or FreeBSD's system users (`-pw`). LDAP is not supported.

## How it works

- For a passwd-file and SQL, `doveadm pw -t` verifies the current
  password and `doveadm pw -s` hashes the new one, which is verified
  before it is stored. Dovecot's own code handles every scheme it knows;
  passwords reach doveadm on standard input, never the command line.
  Plaintext schemes are refused.
- A wrong password and an unknown user get the same answer, after three
  seconds. Five failures within ten minutes pause the user (fail2ban's
  defaults); a restart clears the count.
- At most 16 conversations at once, each bounded to 30 seconds.

### passwd-file

- The file is replaced atomically: the new content goes to a file beside
  it with the old one's mode, owner and group, and is renamed over it.
  Only the one user's password field changes.
- Writers are serialised by `flock` on `<file>.lock`, which scripts can
  take with `flock(1)`. The current password is checked again under the
  lock, so a change made in between is not overwritten.

### SQL

`-sql /etc/dovecot/passwd.sql` names a file, readable by the service
only since it holds the database password:

    # pgsql (PostgreSQL), mysql (MySQL, MariaDB) or sqlite
    driver = pgsql
    dsn = host=/run/postgresql dbname=mail user=passwd
    select = SELECT password FROM users WHERE userid = '%{user | username}' AND domain = '%{user | domain}' FOR UPDATE
    update = UPDATE users SET password = '%{hash}' WHERE userid = '%{user | username}' AND domain = '%{user | domain}'

- `select` returns one row: none is an unknown user, two are an error.
  The hash is the column named `password`, as in Dovecot's
  `password_query`. A hash without a `{SCHEME}` prefix takes
  `-default-scheme`, as does any hash in a column named
  `password_noscheme`.
- Variables follow Dovecot 2.3 or 2.4: `%u` or `%{user}` the user as
  sent, `%n` or `%{user | username}` its local part, `%d` or
  `%{user | domain}` its domain, the filters `lower` and `upper` (`%Lu`),
  `%%` a percent sign. In `update` only, `%p` or `%{hash}` is the new
  hash with its prefix, and `%h` or `%{hash | noscheme}` the hash without
  it, for a database that leaves the scheme to Dovecot's
  `default_password_scheme` (`-scheme` must then equal
  `-default-scheme`). Dovecot 2.3's `%h`, the home, is not taken.
- Variables are bound as parameters, never pasted into the SQL; a quoted
  literal holding them is bound whole, so `'%n'` and `'/var/vmail/%d/%n'`
  work as written. A query copied from Dovecot needs only `FOR UPDATE`.
- The select, the check and the update run in one transaction; an update
  changing anything but one row is rolled back. On SQLite, which has no
  `FOR UPDATE`, add `_txlock=immediate` to the DSN.
- The DSN is the Go driver's: [pgx](https://github.com/jackc/pgx) takes
  Dovecot's pgsql `connect` line as is;
  [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql#dsn-data-source-name)
  takes `user:password@unix(/run/mysqld/mysqld.sock)/mail`;
  [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) a path or
  `file:` URI.
- Each driver is built in only with its build tag: `go build -tags pgsql`.
  Without one the binary depends on nothing beyond Go's standard library.

### FreeBSD system users

With `-pw /usr/sbin/pw`, Dovecot's auth service verifies the current
password over its auth-client socket (`-auth-socket`), through whatever
passdb Dovecot signs in with, usually PAM; `-auth-service` is the
protocol the passdb sees. `pw usermod -n <user> -h 0` then reads the
new password from standard input and hashes it as the user's login
class says. No password or hash appears on a command line.

- pw needs root, so the service runs as root. Listen on a socket in a
  directory of alborz's group (`-listen unix:/var/run/alborz-passwd/sock`,
  the directory `root:alborz 0750`) with umask 007, so the group can
  connect.
- alborz sends the local part (`?user=local`), as PAM names users.
- Any account Dovecot's passdb accepts can be changed, root's too if PAM
  lets root sign in to Dovecot; deny such accounts in the passdb.
- The current password is checked again just before pw runs, but a
  change made in between by another tool is overwritten.
- Only the local password database changes, not LDAP or Kerberos behind
  PAM.
- OpenBSD's and NetBSD's tools take the new hash as an argument, visible
  in `ps`, so they are not supported.

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

The unit serves a passwd-file. For `-sql`, change `ExecStart`; the
directory and `CAP_CHOWN` are then not needed, and a database over TCP
needs `PrivateNetwork`, `RestrictAddressFamilies` and `IPAddressDeny`
loosened.

Flags: `-passwd-file`, `-sql` or `-pw` (exactly one), `-scheme` (new
hashes, default `SHA512-CRYPT`), `-default-scheme` (default `CRYPT`),
`-min-length` (default 8), `-doveadm`, `-auth-socket` (default
`/var/run/dovecot/auth-client`), `-auth-service` (default `imap`),
`-listen` (`unix:/path` or a loopback `host:port`; unset takes the
socket systemd passes).

## Security notes

- The protocol is plain text, so the service refuses to listen anywhere
  but a Unix socket or a loopback address. The socket unit admits only
  the `alborz` group; a loopback port is open to every local user.
- `doveadm pw -t` takes the stored hash as an argument; the unit hides
  the service's processes from other users (`ProtectProc=invisible`).
- A passwd-file service needs to write the file's directory and
  `CAP_CHOWN`; the unit grants nothing else.
- With Dovecot's `auth_cache_size` set, the old password works until
  its cache entry expires: run `doveadm auth cache flush <user>` or leave
  the cache off.
- No password reset: proving identity without the password is not this
  service's job.

## Test

    go test ./...
    # SQLite in process; PostgreSQL and MySQL where a DSN is given:
    PGSQL_DSN=postgres://... MYSQL_DSN='user:pw@tcp(127.0.0.1:3306)/db' \
      go test -tags pgsql,mysql,sqlite ./...
    # doveadm against a real Dovecot:
    GOOS=linux go test -c -o passwd.test . &&
      docker run --rm -v $PWD/passwd.test:/t:ro -e DOVEADM=/dovecot/bin/doveadm \
        --entrypoint /t dovecot/dovecot:2.4.5 -test.v
    # Dovecot's auth service (static passdb):
    GOOS=linux go test -c -o passwd.test . && docker run -d --name dc \
        -e USER_PASSWORD=secret dovecot/dovecot:2.4.5 && docker cp passwd.test dc:/t &&
      docker exec -e AUTH_SOCKET=/run/dovecot/auth-client -e AUTH_USER=alice \
        -e AUTH_PASSWORD=secret dc /t -test.v -test.run DovecotAuth
