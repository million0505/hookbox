# Hookbox

A small, local webhook inbox for checking JSON integrations before pointing them at a live service. Python 3.9+, SQLite, no third-party dependencies.

Send an event, inspect the stored payload, and check the headers your integration actually emitted. The server binds only to `127.0.0.1`.

## Run

```sh
python3 -B hookbox.py --db ./hookbox.sqlite3
```

In another terminal:

```sh
python3 -B send_example.py
curl http://127.0.0.1:8767/events
curl http://127.0.0.1:8767/events/1
```

`send_example.py` sends synthetic order data to `/hooks/orders`. A successful POST returns HTTP 201 and the detail path. `GET /events` lists the most recent 100 event summaries. `GET /events/ID` returns the payload and filtered headers.

An existing database requires `--resume`. Use `--keep 250` to change retention (1–1000 events). New database files are created with owner-only permissions on systems that support Unix file modes. Database files and local environment files are excluded by `.gitignore`.

## Optional authentication and signatures

Set `HOOKBOX_TOKEN` (at least 16 characters) in the server environment to require `Authorization: Bearer ...` on all routes. Set `HOOKBOX_SIGNING_SECRET` to verify a body signature on incoming POSTs:

```text
X-Hookbox-Signature: sha256=<lowercase HMAC-SHA256 of the raw request bytes>
```

The example sender reads the same environment variables. Do not put live secrets into committed files or command-line arguments. Signature verification happens on the original bytes before JSON decoding.

## Request rules

- POST route: `/hooks/NAME`, where NAME contains 1–80 letters, digits, `_` or `-`.
- `Content-Type: application/json` and one valid `Content-Length` are required.
- Maximum body: 64 KiB. Chunked transfer is not supported.
- Invalid UTF-8, duplicate object keys and non-finite values are rejected.
- Authorization, cookie, token, secret, signature and API-key header names are redacted in stored records. URL query strings are not retained.
- Old records are pruned in the same database transaction as each accepted event.

The body itself is **not** scrubbed: it may contain sensitive application data. Use synthetic examples and keep the database private. This is a single-process development tool, not an Internet-facing webhook gateway. It does not provide TLS, public tunnels, production concurrency, replay delivery, or a filesystem sandbox. Cross-origin browser requests are not enabled.

## Test

```sh
python3 -B -m unittest -v test_hookbox.py
```

Tests run a real loopback HTTP server with a temporary database. They exercise receipt/retrieval, Unicode payloads, leading-zero IDs, header redaction, retention, bearer checks, HMAC failures, malformed JSON, body limits, content type, and browser preflight rejection.

The `release/v0.1` branch keeps the initial handoff version available separately from ongoing changes.

## License

MIT. See [LICENSE](LICENSE).
