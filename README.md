# JWKS Service

Generates RSA signing keys and serves their public halves as a JSON Web Key
Set (JWKS, [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)) at
`/.well-known/jwks.json`, so token verifiers can fetch your public keys over
HTTPS. Private keys never leave the server.

- Keys are RSA (2048-bit minimum) for `RS256` signatures.
- Each key's `kid` is its [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)
  SHA-256 thumbprint, so kids are deterministic and collision-free.
- Private keys are stored as PEM files in `working/keys/` (owner-only
  permissions, outside the web document root). Override the location with the
  `JWKS_KEYS_DIR` environment variable.

## Setup

This project uses [Composer](https://getcomposer.org/) for package and script
management. Install Composer by following the instructions at
<https://getcomposer.org/download/>, then install the project dependencies:

```sh
composer install
```

Requirements: PHP >= 8.3 with the `openssl` and `json` extensions.

## CLI commands

All key management goes through `bin/jwks`:

| Command | Purpose |
| --- | --- |
| `bin/jwks generate [bits]` | Generate a new RSA signing key (default 2048 bits, minimum 2048) and add it to the key set |
| `bin/jwks list` | List the `kid` of every key in the key set |
| `bin/jwks retire <kid>` | Permanently remove a key from the key set |
| `bin/jwks show` | Print the public JWKS document as JSON |
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
4. Verify: `curl https://your-host/.well-known/jwks.json`.

The `DocumentRoot` must point at `public/` — the project root and
`working/keys` stay outside it, so private keys are never web-accessible.
Routing uses `FallbackResource` (set in the vhost, or via
[public/.htaccess](public/.htaccess) if your setup allows overrides).

Responses carry `Cache-Control: public, max-age=300`, so verifiers may cache
the key set for up to 5 minutes.

## Key rotation

1. `bin/jwks generate` — the new key is published alongside the old one
   immediately.
2. Start signing new tokens with the new key (`bin/jwks list` shows the kid;
   the private PEM is `working/keys/<kid>.pem`).
3. After every token signed with the old key has expired (plus the 5-minute
   response cache window), remove it: `bin/jwks retire <old-kid>`.

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
| `src/` | Library code (key generation, key store, JWKS building, HTTP endpoint, CLI) |
| `public/` | Web document root — `index.php` front controller only |
| `bin/` | `jwks` CLI and `serve` dev-server launcher |
| `docs/` | Apache virtual-host example |
| `tests/` | PHPUnit suite |
| `working/` | Generated data: private keys (`working/keys/`), tool caches — never commit |
