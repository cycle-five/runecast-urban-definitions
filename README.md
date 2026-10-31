# runecast-urban-definitions

A small service that holds Urban Dictionary definitions (2016 snapshot, written
by its users) in memory for RuneCast. Nobody ships the data: a player unlocks
it by uploading their own copy of the dump from their browser.

- Root crate `urban-definitions-wire`: wire types and HMAC-signed upload tickets
  (shared with the backend by git rev).
- `service/`: the service binary (`urban-definitions-service`).

## The key mechanism

The backend hands a player a single-use, 30-minute ticket (HMAC-SHA256 with
`URBAN_DEFINITIONS_KEY`) naming them. The page uploads the file in 8 MiB chunks;
the service hashes it as it arrives and compares the SHA-256 against a list of
known files compiled into the binary. A match proves the player has the file:
the service tells the backend to unlock them, and, if it was empty, the first
matching upload (which was parsed as it streamed) becomes the published index.

## Never on disk

Nothing from the dump touches disk or a database: not the file, not the
definitions, not a cache. Bytes are hashed and parsed in memory and dropped.
Definition text and tickets are never logged.

## Routes

Public (nginx forwards `/urban-definitions/`):

| Route | |
| --- | --- |
| `POST /urban-definitions/uploads` | `StartUpload` -> 201 `StartedUpload` |
| `PUT /urban-definitions/uploads/{id}/chunks/{offset}` | raw body -> 200 `ChunkResponse` |
| `GET /urban-definitions/uploads/{id}` | progress, or the final answer once finished |
| `DELETE /urban-definitions/uploads/{id}` | 204 |
| `GET /urban-definitions/metrics` | Prometheus; `Authorization: Bearer $METRICS_AUTH_TOKEN` |

Errors are `{"error": "<code>"}`: 400 `wrong_size`/`wrong_offset`/`chunk_too_large`/`wrong_file`,
401 `bad_ticket`/`ticket_expired`/`ticket_used`, 404 `not_found`, 409 `busy`,
429 `too_many_uploads`. A finished upload's final answer is kept for 10 minutes, so
re-sending the last chunk (a lost response) returns the same answer and never unlocks twice.

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

Licensed under MIT OR Apache-2.0.
