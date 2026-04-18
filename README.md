# soup-rendezvous

Coordination protocol for multi-party Bitcoin signing, built on Nostr.

Users publish signed events to standard Nostr relays to find each other and form cohorts before running MuSig2, FROST, or covenant signing ceremonies. No custom server — any Nostr relay works out of the box.

Built for [Soup Wallet](https://github.com/8144225309/superscalar-wallet) and [SuperScalar](https://github.com/8144225309/superscalar) channel factories. Scheme-agnostic — the same event kinds work for any multi-party signing scheme without changes.

## How it works

Five Nostr event kinds handle the full lifecycle:

| Kind | Name | Visibility | Purpose |
|------|------|-----------|---------|
| 38100 | advertisement | public | host posts a factory opening with rules and capacity |
| 38101 | vouch | public | coordinator attests a host proved control of an LN node |
| 38102 | status update | public | host posts slot-fill updates ("3/8 joined") |
| 38200 | attestation | encrypted | joiner requests to join (NIP-44 encrypted to host) |
| 38300 | seal | encrypted | host closes the cohort (NIP-44 encrypted to each member) |

A **coordinator** publishes a root discovery thread and vouches for factory hosts after verifying they control a real Lightning node. Wallets browse advertisements, check vouches, and join by publishing encrypted attestations. When the host seals the cohort, each member receives an encrypted manifest with the full member list and connection info. The seal is the handoff — after it, the wallet peers with the LSP over Lightning and all signing, state updates, and factory operations flow over the direct LN connection (custommsg 33001). Nostr is not involved after the seal.

## Spam resistance

Proof-of-node: factory hosts prove control of a Lightning node by signing a challenge with CLN's `signmessage`. The coordinator verifies with `checkmessage` and publishes a vouch. Wallets filter unvouched advertisements by default. Spammers need to operate real LN nodes with funded channels. Legitimate hosts already have one.

## CLI tool

The repo includes a Rust CLI for the coordinator and for testing the full flow:

```
soup-rendezvous init              generate a Nostr keypair
soup-rendezvous publish-root      post the root discovery thread
soup-rendezvous test-ad <root>    post a factory advertisement
soup-rendezvous update-status     post slot-fill status updates
soup-rendezvous list-ads          browse factories from relays
soup-rendezvous challenge         generate a proof-of-node challenge
soup-rendezvous vouch             verify an LN node proof and publish a vouch
soup-rendezvous list-vouches      list verified node proofs
soup-rendezvous join <ad>         publish an encrypted join request
soup-rendezvous review-joins      decrypt and review join requests (host)
soup-rendezvous accept            accept a joiner with encrypted confirmation DM (host)
soup-rendezvous seal <ad>         seal the cohort with accepted members (host)
soup-rendezvous show-cohort <ad>  view the full cohort state
```

## Integration

See [WALLET_INTEGRATION.md](./WALLET_INTEGRATION.md) for the full protocol contract: event schemas, Nostr subscription filters, NIP-44 encryption, proof-of-node verification, seal manifest structure, rules-hash enforcement at signing time, and post-factory communication patterns.

## Status

Early prototype. The CLI is functional and tested live against real Nostr relays (nos.lol, relay.damus.io) with proof-of-node verification against a real CLN signet node.

## License

MIT
