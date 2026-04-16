# soup-rendezvous

Coordination protocol for multi-party Bitcoin signing, built on Nostr.

Users publish signed events to standard Nostr relays to find each other and form cohorts before running MuSig2, FROST, or covenant signing ceremonies elsewhere. No custom server — any Nostr relay works out of the box.

Built for [Soup Wallet](https://github.com/8144225309/superscalar-wallet) and [SuperScalar](https://github.com/8144225309/superscalar) channel factories. Scheme-agnostic — the same event kinds work for any multi-party signing scheme.

## How it works

Three Nostr event kinds form a membership ledger:

1. **Advertisement** (kind 38100) — a host posts a cohort opening with rules and capacity
2. **Attestation** (kind 38200) — a joiner agrees to a specific advertisement
3. **Seal** (kind 38300) — the host closes the cohort with a manifest of accepted members

The seal is the handoff. After it's published, participants run their signing ceremony over whatever transport the scheme uses (for SuperScalar, that's bLIP-56 over Lightning peer messaging). Post-cohort communication between the LSP and members uses the same Nostr relays via NIP-44 encrypted DMs.

## Spam resistance

Proof-of-node: wallets prove control of a Lightning node via CLN's signmessage. Spammers need to operate real LN nodes with funded channels. Legitimate users already have one.

## Status

Early prototype. The repo contains a working reference server (phases 0-4, 57 tests) that validated the protocol design. Production deployments will point wallets at standard Nostr relays instead.

## License

MIT
