# JWKS Service

Generates RSA signing keys and serves their public halves as a JSON Web Key
Set (JWKS, [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)) at
`/.well-known/jwks.json` (and at `/` for convenience), so token verifiers can
fetch your public keys over HTTPS. Private keys never leave the server.

- Keys are RSA (2048-bit minimum) for `RS256` signatures.
- Each key's `kid` is its [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)
  SHA-256 thumbprint, so kids are deterministic and collision-free.
- Keys rotate automatically on a D2L-style schedule: 30-day lifetime, a
  successor 7 days before expiry, and a 1-hour warm-up before a new key may
  sign. See [Key rotation](#key-rotation).
- Private keys are stored as PEM files in `working/keys/` (owner-only
  permissions, outside the web document root), each with a `<kid>.json`
  sidecar recording its rotation schedule. Override the location with the
  `JWKS_KEYS_DIR` environment variable.

## Setup

This project uses [Composer](https://getcomposer.org/) for package and script
management. Install Composer by following the instructions at
<https://getcomposer.org/download/>, then install the project dependencies:

```sh
composer install
```

Requirements: PHP >= 8.4 with the `openssl` and `json` extensions (the code
uses PHP 8.4 syntax such as method calls on `new` without parentheses).

Optionally copy [.env.example](.env.example) to `.env` at the project root
to configure the service (key directory, rotation timing, key size). Both
the CLI and the web endpoint read it; real environment variables always win
over the file. Each line is `KEY=VALUE` — inline `#` comments are not
supported (the `#` and everything after it become part of the value).

## CLI commands

All key management goes through `bin/jwks`:

| Command | Purpose |
| --- | --- |
| `bin/jwks generate [bits]` | Generate a new RSA signing key (default `JWKS_KEY_BITS` or 2048 bits, range 2048–8192) and add it to the key set |
| `bin/jwks list` | List every key with its lifecycle state (`legacy`/`pending`/`active`/`expired`) and timing |
| `bin/jwks retire <kid>` | Permanently remove a key from the key set |
| `bin/jwks rotate` | Run one rotation pass: schedule legacy keys for replacement, generate a successor when needed, purge long-expired keys |
| `bin/jwks show` | Print the public JWKS document as JSON |
| `bin/jwks signing-key` | Print the `kid` and PEM path of the key the token issuer should sign with |
| `bin/jwks status` | Health check for monitoring: exit 0 when healthy, exit 1 with `DEGRADED:` reasons when not |
| `bin/jwks help` | Show usage |

Exit code is `0` on success and `1` on any error; errors are written to
stderr.

## Local testing with the built-in PHP web server

```sh
bin/jwks generate
bin/serve                 # serves http://127.0.0.1:8080
curl http://127.0.0.1:8080/.well-known/jwks.json
```

`bin/serve` accepts an optional `host:port` argument, e.g.
`bin/serve 0.0.0.0:9000`. `composer serve` does the same on the default
address. The built-in server is for local testing only — production traffic
runs under Apache.

## Production deployment (Apache + HTTPS)

1. Deploy the project to the server (e.g. `/var/www/jwks`) and run
   `composer install --no-dev` there.
2. Generate the first signing key on the server: `bin/jwks generate`.
   Ensure `working/keys` is owned by the user Apache/PHP runs as, readable by
   no one else (the tool creates it mode `0700`, key files mode `0600`).
3. Copy [docs/apache-vhost.conf.example](docs/apache-vhost.conf.example) into
   your Apache config, adjust `ServerName`, `DocumentRoot`, and the paths to
   your existing HTTPS certificate, then reload Apache.
4. Install the hourly `bin/jwks rotate` cron entry (see
   [Key rotation](#key-rotation)) as the same user that owns `working/keys`.
5. Install [docs/jwks-logrotate.example](docs/jwks-logrotate.example) as
   `/etc/logrotate.d/jwks` and point your monitoring at `bin/jwks status`
   (see [Monitoring](#monitoring)).
6. Decide on key backups: either back up `working/keys` securely (the PEMs
   are the only copies, and kids are deterministic thumbprints, so restoring
   the files restores the identical key set), or accept that after a disk
   loss every token signed before the loss stays unverifiable until it
   expires.
7. Verify: `curl https://your-host/.well-known/jwks.json`.

The `DocumentRoot` must point at `public/` — the project root and
`working/keys` stay outside it, so private keys are never web-accessible.
Routing uses `FallbackResource` (set in the vhost, or via
[public/.htaccess](public/.htaccess) if your setup allows overrides).

Responses carry `Cache-Control: public, max-age=300`, so verifiers may cache
the key set for up to 5 minutes, and `Access-Control-Allow-Origin: *` so
browser-based verifiers can read the key set (it holds only public keys).

## Key rotation

Rotation is automatic, modeled on how D2L Brightspace rotates its JWKS keys:
every key expires 30 days after creation, a successor is generated 7 days
before that expiry, and a new key signs nothing for its first hour so
verifier caches (5-minute window) always see a key before its first token.
Published keys carry their expiry as an `exp` member, as D2L's do.

Run one rotation pass per hour from cron on the server:

```cron
0 * * * * /var/www/jwks/bin/jwks rotate >> /var/www/jwks/working/rotate.log 2>&1
```

`rotate` is idempotent and only acts when something needs doing:

- Keys created before rotation existed ("legacy" keys, no `<kid>.json`
  sidecar) are scheduled for replacement: a successor is generated at once
  and the legacy key expires 7 days later.
- A successor is generated when the newest key enters its final 7 days; both
  keys are served during the overlap.
- Keys expired more than 7 days ago are deleted, PEM and sidecar.

The token issuer should ask which key to sign with instead of hardcoding a
kid:

```sh
bin/jwks signing-key     # prints: <kid> <path-to-private-pem>
```

For example, with `firebase/php-jwt` in the issuing application:

```php
[$kid, $pemPath] = explode(' ', trim(shell_exec('/var/www/jwks/bin/jwks signing-key')), 2);

$jwt = Firebase\JWT\JWT::encode(
    ['iss' => 'https://your-host', 'sub' => $userId, 'exp' => time() + 3600],
    file_get_contents($pemPath),
    'RS256',
    $kid, // verifiers use the kid header to pick the key from the JWKS
);
```

Rotation timing and key size are configurable through environment variables,
set in the real environment or in a `.env` file at the project root (copy
[.env.example](.env.example)); the real environment wins:

| Variable | Default | Meaning |
| --- | --- | --- |
| `JWKS_KEY_LIFETIME` | `2592000` (30 d) | Seconds a key lives after creation |
| `JWKS_ROTATION_BUFFER` | `604800` (7 d) | Seconds before expiry that a successor appears; also the purge grace period |
| `JWKS_TIME_UNTIL_USE` | `3600` (1 h) | Seconds a new key is published before it may sign |
| `JWKS_KEY_BITS` | `2048` | RSA size of newly generated keys (2048–8192) |
| `JWKS_LOG_FILE` | `working/jwks.log` | Where key activity and errors are logged |

The rotation buffer must exceed the lifetime of any token you sign — a token
must always expire before the key that signed it leaves the key set. Manual
`bin/jwks generate` and `bin/jwks retire` still work for emergencies (e.g.
revoking a compromised key immediately).

Concurrent rotation passes serialize on `rotate.lock` in the keys directory,
so an overlapping cron run and manual rotate cannot both generate a
successor. The lock uses `flock`, so the keys directory must live on a
local filesystem — one host, not NFS.

### Monitoring

Point your monitoring at `bin/jwks status`: it exits 0 when the key set is
healthy and 1 with one `DEGRADED: <reason>` line per problem (empty key set,
legacy keys awaiting rotation, every key expired, or rotation overdue —
the newest key inside its final rotation buffer with no successor). Every
degraded state means the rotate cron is missing, dead, or has not run yet.
Without monitoring, a dead cron looks fine for ~23 days and then the key
set expires and every verifier breaks at once.

External uptime monitors can use `GET /healthz` instead: it returns
`200 {"status":"ok"}` or `503 {"status":"degraded"}` with
`Cache-Control: no-store`. The degraded reasons deliberately stay off the
wire — run `bin/jwks status` on the box for detail.

## Logging

Every key activity and failure is recorded in `working/jwks.log` (override
with `JWKS_LOG_FILE`), one UTC ISO-8601 timestamped line per event:

- `INFO` — key generated, retired, scheduled for replacement, or purged;
  plus an hourly "nothing to rotate" heartbeat proving the cron job is alive.
- `ERROR` — failed CLI commands and endpoint errors (the endpoint still
  answers with a JSON 500).

Read-only commands (`list`, `show`, `signing-key`, `status`) and normal
JWKS fetches are not logged — the web server's access log already covers
fetches. If the log file cannot be written, lines fall back to PHP's
`error_log` rather than failing the command or request.

The log grows without bound otherwise; install
[docs/jwks-logrotate.example](docs/jwks-logrotate.example) as
`/etc/logrotate.d/jwks` in production.

## Development checks

```sh
composer test    # PHPUnit test suite (includes a real end-to-end server test)
composer stan    # phpstan static analysis, level 9
composer cs      # phpcs, PSR-12
composer check   # all of the above
```

The manual test walkthrough lives in [TESTPLAN.md](TESTPLAN.md).

## Layout

| Path | Purpose |
| --- | --- |
| `src/` | Library code (key generation, key store, rotation lifecycle, JWKS building, HTTP endpoint, CLI) |
| `public/` | Web document root — `index.php` front controller only |
| `bin/` | `jwks` CLI and `serve` dev-server launcher |
| `docs/` | Apache virtual-host example |
| `tests/` | PHPUnit suite |
| `working/` | Generated data: private keys (`working/keys/`), logs (`working/jwks.log`), tool caches — never commit |
