# soup-rendezvous

Content-addressed coordination server for multi-party Bitcoin signing. Users post signed events to find each other and form cohorts before running MuSig2, FROST, or covenant signing ceremonies elsewhere.

Built for [Soup Wallet](https://github.com/8144225309/superscalar-wallet) and [SuperScalar](https://github.com/8144225309/superscalar) channel factories. Scheme-agnostic — the same server hosts any multi-party signing scheme without changes.

## How it works

The server is a dumb store. It accepts opaque JSON events, content-addresses them by `sha256(body)`, and serves them back. It never verifies signatures or parses scheme payloads — wallets and LSPs do that.

Three event types flow through the server:

1. **Advertisement** — a host posts a cohort opening with rules
2. **Attestation** — a joiner agrees to a specific advertisement
3. **Seal** — the host closes the cohort with a manifest of accepted joiners

The seal is the handoff. After it's published, the server is done and the participants run their signing ceremony over whatever transport the scheme uses.

## API

```
POST   /v0/events                 publish an event (idempotent)
GET    /v0/events/{id}            fetch by content hash
GET    /v0/events?kind=&scheme=   list with filters
GET    /v0/cohorts/{id}           full cohort view (ad + attestations + seal)
GET    /v0/health                 liveness
```

## Run

```
cargo build --release
./target/release/soup-rendezvous --db soup.db --bind 127.0.0.1:8090
```

All options configurable via flags or `SOUP_*` env vars. See `--help`.

## Status

Early prototype. Rate limiting, body size caps, clock-skew rejection, and per-key storage quotas are in place. Not yet deployed for production use.

## License

MIT
