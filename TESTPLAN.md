# Test Plan

Manual walkthrough of every command and endpoint. Keep this document current
whenever commands or functionality change. The automated suite
(`composer check`) covers the same ground and must pass before working
through this list.

## Automated checks

- [ ] `composer test` — full PHPUnit suite passes (47 tests, includes real end-to-end built-in-server test)
- [ ] `composer stan` — phpstan level 9 reports no errors
- [ ] `composer cs` — phpcs reports no PSR-12 violations

## CLI: bin/jwks

### generate

- [ ] `bin/jwks generate` prints `Generated key <kid>` and exits 0
- [ ] `working/keys/<kid>.pem` exists with permissions `0600`, directory `working/keys` is `0700`
- [ ] `bin/jwks generate 3072` creates a 3072-bit key (`openssl rsa -in working/keys/<kid>.pem -noout -text | head -1` shows 3072)
- [ ] `bin/jwks generate 1024` prints an error to stderr and exits 1 (below 2048-bit minimum)
- [ ] `bin/jwks generate huge` prints an error to stderr and exits 1 (non-numeric bits)

### list

- [ ] With keys present, `bin/jwks list` prints one kid per line and exits 0
- [ ] With no keys, `bin/jwks list` prints `No keys in the key set…` and exits 0

### show

- [ ] `bin/jwks show` prints valid JSON with a `keys` array containing one entry per stored key
- [ ] Each entry has exactly `kty`, `use`, `alg`, `kid`, `n`, `e` — no private members (`d`, `p`, `q`, …)

### retire

- [ ] `bin/jwks retire <kid>` removes `working/keys/<kid>.pem`, prints confirmation, exits 0
- [ ] `bin/jwks retire unknown-kid` prints an error to stderr and exits 1
- [ ] `bin/jwks retire` (no kid) prints an error to stderr and exits 1

### help / usage

- [ ] `bin/jwks help` prints usage and exits 0
- [ ] `bin/jwks` (no command) prints usage to stderr and exits 1
- [ ] `bin/jwks frobnicate` prints usage to stderr and exits 1

## Local endpoint: built-in PHP web server

- [ ] `bin/serve` starts and prints the URL (default `127.0.0.1:8080`)
- [ ] `bin/serve 127.0.0.1:9000` serves on the given address
- [ ] `composer serve` also starts the server
- [ ] `curl -i http://127.0.0.1:8080/.well-known/jwks.json` returns `200`, `Content-Type: application/json`, `Cache-Control: public, max-age=300`, and the key set
- [ ] `curl -i http://127.0.0.1:8080/anything-else` returns `404` with a JSON error body
- [ ] `curl -i -X POST http://127.0.0.1:8080/.well-known/jwks.json` returns `405` with `Allow: GET, HEAD`
- [ ] `curl -I http://127.0.0.1:8080/.well-known/jwks.json` (HEAD) returns `200`

## Production endpoint: Apache + HTTPS

- [ ] Virtual host from `docs/apache-vhost.conf.example` installed with real `ServerName`, `DocumentRoot`, and certificate paths; Apache reloads without errors
- [ ] `curl -i https://<host>/.well-known/jwks.json` returns `200` with the key set over HTTPS
- [ ] `curl -i http://<host>/.well-known/jwks.json` redirects (301) to HTTPS
- [ ] `curl -i https://<host>/index.php` returns `404` JSON (front controller handles it; nothing else is exposed)
- [ ] Private keys are not reachable: `curl -i https://<host>/../working/keys/` and any path outside `public/` return errors
- [ ] `working/keys` on the server is `0700`, owned by the PHP runtime user

## Key rotation walkthrough

- [ ] With key A live, `bin/jwks generate` adds key B; endpoint immediately serves both A and B
- [ ] `bin/jwks retire <kid-A>` removes A; endpoint serves only B (allow up to 5 minutes for verifier caches)
