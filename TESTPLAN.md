# Test Plan

Manual walkthrough of every command and endpoint. Keep this document current
whenever commands or functionality change. The automated suite
(`composer check`) covers the same ground and must pass before working
through this list.

## Automated checks

- [ ] `composer test` — full PHPUnit suite passes (127 tests, includes real end-to-end built-in-server test)
- [ ] `composer stan` — phpstan level 9 reports no errors
- [ ] `composer cs` — phpcs reports no PSR-12 violations

## CLI: bin/jwks

### generate

- [ ] `bin/jwks generate` prints `Generated key <kid>` and exits 0
- [ ] `working/keys/<kid>.pem` exists with permissions `0600`, directory `working/keys` is `0700`
- [ ] `bin/jwks generate 3072` creates a 3072-bit key (`openssl rsa -in working/keys/<kid>.pem -noout -text | head -1` shows 3072)
- [ ] `bin/jwks generate 1024` prints an error to stderr and exits 1 (below 2048-bit minimum)
- [ ] `bin/jwks generate 16384` prints an error to stderr and exits 1 (above 8192-bit maximum)
- [ ] `bin/jwks generate huge` prints an error to stderr and exits 1 (non-numeric bits)
- [ ] With `JWKS_KEY_BITS=3072` (environment or `.env`), `bin/jwks generate` with no argument creates a 3072-bit key; an explicit `[bits]` argument still wins

### list

- [ ] With keys present, `bin/jwks list` prints one kid per line and exits 0
- [ ] With no keys, `bin/jwks list` prints `No keys in the key set…` and exits 0

### show

- [ ] `bin/jwks show` prints valid JSON with a `keys` array containing one entry per stored key
- [ ] Each entry has exactly `kty`, `use`, `alg`, `kid`, `n`, `e` — no private members (`d`, `p`, `q`, …)

### retire

- [ ] `bin/jwks retire <kid>` removes `working/keys/<kid>.pem` and its `<kid>.json` sidecar, prints confirmation, exits 0
- [ ] `bin/jwks retire unknown-kid` prints an error to stderr and exits 1
- [ ] `bin/jwks retire` (no kid) prints an error to stderr and exits 1

### rotate

- [ ] On an empty key set, `bin/jwks rotate` prints `Generated key <kid>` and creates PEM + `<kid>.json` sidecar (both `0600`)
- [ ] An immediate second `bin/jwks rotate` prints `Key set is current; nothing to rotate.`
- [ ] With a legacy key (PEM without sidecar), `bin/jwks rotate` prints `Scheduled legacy key <kid> for replacement` plus `Generated key <kid>` and both keys remain
- [ ] A key expired more than `JWKS_ROTATION_BUFFER` ago is purged: `Purged expired key <kid>`, PEM and sidecar gone
- [ ] `JWKS_KEY_LIFETIME` / `JWKS_ROTATION_BUFFER` / `JWKS_TIME_UNTIL_USE` override the timing; invalid values print an error and exit 1
- [ ] Two simultaneous `bin/jwks rotate` runs on an empty key set generate exactly one key (serialized on `rotate.lock`)

### signing-key

- [ ] `bin/jwks signing-key` prints `<kid> <pem-path>` of the newest usable key and exits 0
- [ ] With no keys, `bin/jwks signing-key` prints an error to stderr and exits 1

### status

- [ ] With a fresh key, `bin/jwks status` prints `OK: key set is healthy` and exits 0
- [ ] With no keys, prints `DEGRADED: key set is empty…` and exits 1
- [ ] With a legacy key (no sidecar), prints `DEGRADED: legacy key <kid> awaiting first rotation` and exits 1
- [ ] With the newest key inside its rotation buffer and no successor, prints `DEGRADED: rotation overdue…` and exits 1
- [ ] `status` writes no log lines

## Logging

- [ ] `bin/jwks generate` / `retire` / `rotate` append timestamped `INFO` lines to `working/jwks.log`
- [ ] An idle `bin/jwks rotate` logs the "nothing to rotate" heartbeat line
- [ ] A failed command (e.g. `bin/jwks retire unknown-kid`) appends an `ERROR` line
- [ ] An endpoint failure (e.g. corrupt PEM in the keys directory) returns JSON 500 and appends an `ERROR endpoint:` line
- [ ] `JWKS_LOG_FILE` (environment or `.env`) relocates the log
- [ ] `list`, `show`, and `signing-key` do not write log lines
- [ ] With an unwritable log path, commands still succeed and lines land in PHP's `error_log`

## Configuration via .env

- [ ] With `.env` at the project root setting `JWKS_KEYS_DIR`, both `bin/jwks` and the endpoint use that directory
- [ ] A real environment variable overrides the same variable in `.env` (e.g. `JWKS_KEY_BITS=2048 bin/jwks generate` beats `.env`'s 3072)
- [ ] A malformed `.env` line makes `bin/jwks` print an error naming the line number and exit 1
- [ ] With no `.env` file, everything runs on defaults

### help / usage

- [ ] `bin/jwks help` prints usage and exits 0
- [ ] `bin/jwks` (no command) prints usage to stderr and exits 1
- [ ] `bin/jwks frobnicate` prints usage to stderr and exits 1

## Local endpoint: built-in PHP web server

- [ ] `bin/serve` starts and prints the URL (default `127.0.0.1:8080`)
- [ ] `bin/serve 127.0.0.1:9000` serves on the given address
- [ ] `composer serve` also starts the server
- [ ] `curl -i http://127.0.0.1:8080/.well-known/jwks.json` returns `200`, `Content-Type: application/json`, `Cache-Control: public, max-age=300`, and the key set
- [ ] `curl -i http://127.0.0.1:8080/` returns `200` with the same key set
- [ ] Keys with a rotation sidecar carry an `exp` member in the JWKS; expired keys are absent from the document
- [ ] Responses carry `Access-Control-Allow-Origin: *`
- [ ] `curl -i http://127.0.0.1:8080/anything-else` returns `404` with a JSON error body
- [ ] `curl -i -X POST http://127.0.0.1:8080/.well-known/jwks.json` returns `405` with `Allow: GET, HEAD`
- [ ] `curl -I http://127.0.0.1:8080/.well-known/jwks.json` (HEAD) returns `200`

## Production endpoint: Apache + HTTPS

- [ ] Virtual host from `docs/apache-vhost.conf.example` installed with real `ServerName`, `DocumentRoot`, and certificate paths; Apache reloads without errors
- [ ] `curl -i https://<host>/.well-known/jwks.json` returns `200` with the key set over HTTPS
- [ ] `curl -i https://<host>/` returns `200` with the same key set
- [ ] `curl -i http://<host>/.well-known/jwks.json` redirects (301) to HTTPS
- [ ] `curl -i https://<host>/index.php` returns `404` JSON (front controller handles it; nothing else is exposed)
- [ ] Private keys are not reachable: `curl -i https://<host>/../working/keys/` and any path outside `public/` return errors
- [ ] `working/keys` on the server is `0700`, owned by the PHP runtime user

## Key rotation walkthrough

- [ ] Hourly cron entry installed: `0 * * * * /var/www/jwks/bin/jwks rotate >> /var/www/jwks/working/rotate.log 2>&1`; output appears in the log
- [ ] When the newest key enters its final rotation-buffer window, `rotate` generates a successor; endpoint serves both during the overlap
- [ ] The token issuer signs with whatever `bin/jwks signing-key` reports; a brand-new key is not reported until it has been published for `JWKS_TIME_UNTIL_USE`
- [ ] One rotation buffer after a key expires, `rotate` purges it from `working/keys`
- [ ] Emergency path still works: `bin/jwks retire <kid>` removes a compromised key immediately; endpoint stops serving it
