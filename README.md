# runecast-urban-definitions

A small service that holds Urban Dictionary definitions in memory for RuneCast,
unlocked by the player's own copy of the file.

- Root crate `urban-definitions-wire`: wire types and HMAC-signed upload tickets
  (shared with the backend by git rev).
- `service/`: the service binary (`urban-definitions-service`).

Licensed under MIT OR Apache-2.0.
