# runecast-urban-definitions

A small service that holds Urban Dictionary definitions (2016 snapshot, written
by its users) in memory for RuneCast. A player unlocks it by proving, in their
browser, that they hold their own copy of the dump.

- Root crate `urban-definitions-wire`: wire types and HMAC-signed tickets
  (shared with the backend by git rev).
- `service/`: the service binary (`urban-definitions-service`).

## The key mechanism

At start the service loads the dump from muninn (below), checking it against a
table of hashes compiled into the binary; nothing is published until the whole
file verified. While it is loading, lookups answer `empty`.

The backend hands a player a single-use, 30-minute ticket (HMAC-SHA256 with
`URBAN_DEFINITIONS_KEY`) naming them. The page trades it for a challenge: 32
random 4 KiB pieces of the file, named by index. The player's browser reads
those pieces from their own copy and sends them back; the service checks each
against the proof table, and a full match proves they hold the file. The service
then tells the backend to unlock them. A challenge lasts 2 minutes and is
single use; at most 256 are open at once.

## Never on disk

Nothing from the dump touches our disk or a database: not the file, not the
definitions, not a cache. muninn holds the one copy; the service streams it
into memory. Tickets, proof bytes and definition text are never logged.

## Routes

Public (nginx forwards `/urban-definitions/`):

| Route | |
| --- | --- |
| `POST /urban-definitions/challenges` | `ChallengeRequest` (body up to 4 KiB) -> 201 `Challenge` |
| `POST /urban-definitions/challenges/{id}/proof` | raw body, the named pieces in order (up to 128 KiB) -> 200 `ProofResponse` |
| `GET /urban-definitions/metrics` | Prometheus; `Authorization: Bearer $METRICS_AUTH_TOKEN` |

Errors are `{"error": "<code>"}`: 400 `wrong_file`; 401 `bad_ticket`/`ticket_expired`/`ticket_used`;
404 `not_found`; 410 `challenge_expired`; 429 `busy`; 500 `unavailable`; 503 `loading`
(the ticket is not spent). An oversized body is 413. Asking again with a ticket whose
challenge is still open returns the same challenge. A finished proof's answer is kept
for 10 minutes, so re-sending it (a lost response) returns the same answer and never
unlocks twice.

Internal (compose network only; header `X-Internal-Token`):

- `GET /internal/definitions/{word}?glued=true|false` -> `LookupResponse`
- `GET /health` (no token)

The service calls `POST {BACKEND_INTERNAL_URL}/internal/urban-definitions/unlock`
(`X-Internal-Token`, expects 204; three attempts, 1 s apart).

## Environment

| Variable | |
| --- | --- |
| `URBAN_DEFINITIONS_KEY` | required; ticket HMAC key (same as the backend's) |
| `INTERNAL_TOKEN` | required; shared with the backend |
| `METRICS_AUTH_TOKEN` | required; bearer for the metrics route |
| `BACKEND_INTERNAL_URL` | default `http://backend:3001` |
| `BIND_ADDR` | default `0.0.0.0:3003` |

Missing secrets stop startup (fail closed).

## Loading from muninn

The service runs `ssh` to muninn and reads a zstd stream, retrying with backoff
(60 s doubling to 30 min, plus jitter) until it verifies. The key directory is
mounted read-only at `/run/muninn`; the container runs as uid 10003.

| Variable | |
| --- | --- |
| `DUMP_SSH_HOST` | muninn's address; unset or empty means the dump is never loaded |
| `DUMP_SSH_PORT` | default `22` |
| `DUMP_SSH_USER` | required when the host is set |
| `DUMP_SSH_KEY` | default `/run/muninn/id_ed25519` |
| `DUMP_SSH_KNOWN_HOSTS` | default `/run/muninn/known_hosts` |
| `DUMP_SSH_HOST_KEY_ALIAS` | default the host value |

Licensed under MIT OR Apache-2.0.
