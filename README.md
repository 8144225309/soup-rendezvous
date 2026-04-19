# soup-rendezvous

A Nostr-based **seed list** of verified Lightning Service Providers (LSPs) who run multi-party Bitcoin signing factories. Wallets read the list, pick an LSP that passed verification, and dial that LSP directly over Lightning for everything else (factory parameters, slot availability, joining, signing).

Built for [Soup Wallet](https://github.com/8144225309/superscalar-wallet) and [SuperScalar](https://github.com/8144225309/superscalar) channel factories, but scheme-agnostic — nothing about the factory itself lives on Nostr.

## What this is (and isn't)

This repo is a **Nostr DNS-seeder for LSPs**. The coordinator publishes a list of "verified LSP contact pointers" on Nostr, and that's the whole contract. Think of it like Bitcoin Core's hardcoded DNS seeds: a starting point, not a trusted party. Wallets take a contact pointer, call the LSP over Lightning, and do their own end-to-end inspection of whatever the LSP offers. If the LSP lies, misbehaves, or goes offline, the wallet walks away at no protocol cost — no funds at risk at this layer.

What's **not** here and deliberately never will be: factory parameters, slot fill status, join requests, accept/reject flow, seal manifests, signing ceremonies. All of that happens LSP↔wallet directly over Lightning, where the wallet can inspect everything it cares about before committing.

## How it works

Three Nostr event kinds. That's it.

| Kind | Name | Visibility | Purpose |
|------|------|-----------|---------|
| 38099 | root thread | public | coordinator's self-describing identity post (replaceable, d-tag `"root"`) |
| 38101 | vouch | public | one entry in the seed list: "LSP H passed verification tier T, dial them at LN pubkey X" |
| 4 | DM | NIP-44 encrypted | host → coordinator proof request; coordinator → host confirmation |

The full flow:

1. Coordinator publishes a root thread (kind 38099) announcing its npub and description. Wallets either hardcode the npub or add it via a custom-coordinator field in UI.
2. LSP generates a Nostr keypair and sends the coordinator an encrypted kind-4 DM containing one or more proofs (proof-of-channel, proof-of-utxo, proof-of-peer — whatever they qualify for).
3. Coordinator verifies each tier the host submitted, picks the strongest that succeeds, and publishes a vouch (kind 38101) with a NIP-40 expiration.
4. Coordinator DMs a confirmation back to the LSP.
5. Wallets query vouches by tier (`"#l":["channel"]`, then `"#l":["utxo"]`, then `"#l":["peer"]` optionally), take the `ln_node_id` from each, and dial the LSP over Lightning for the actual factory offer.

No ads, no attestations, no seals on Nostr. All factory state lives on the LSP's LN node.

## The vouch — what's in it, what's not

Uniform shape across all three tiers — only the `l` tag value differs:

```
["d",          "<host-nostr-pubkey-hex>"]   # identity, parameterized-replaceable
["p",          "<host-nostr-pubkey-hex>"]   # filterable by host
["ln_node_id", "<ln-pubkey-hex>"]           # the contact — dial this over LN
["l",          "channel" | "utxo" | "peer"] # tier filter
["btc_hash",   "<24-hex>"]                  # utxo-tier ONLY, daemon-internal cap key
["expiration", "<unix-ts>"]                 # NIP-40, self-cleans
```
```json
{
  "status":       "active",
  "ln_node_id":   "03abc...",
  "ln_addresses": ["host:9735"],   // OPTIONAL: only if not in BOLT-7 gossip
  "verified_at":  1776374943,
  "expires_at":   1778966943
}
```

About 150–200 bytes. Everything the coordinator verifies (channel count, capacity, UTXO outpoint, bitcoin address, peer feature bits) is checked and then deliberately stripped before publication — vouches are pure contact pointers, nothing about factory state or host-side topology.

## Freshness: use it or lose it

Every vouch carries a NIP-40 `expiration` tag. If an LSP doesn't re-apply before it passes, conformant relays drop the event and conformant clients ignore it. The list is **self-pruning** — no coordinator polling, no operator cleanup job.

Defaults (adjustable):

| Network | Vouch lifetime | Refresh cadence |
|---------|----------------|-----------------|
| signet / testnet4 | 30 days | LSP re-applies every 2–3 weeks |
| mainnet | 14 days | LSP re-applies weekly-ish |

LSPs can automate refresh with a systemd timer that re-runs the proof DM.

## Per-identifier vouch caps

The coordinator bounds how many simultaneously-active vouches it will issue per verified identifier, tighter as the Sybil anchor weakens:

| Method | Identifier | Default cap |
|--------|------------|-------------|
| channel | LN node pubkey | 10 |
| utxo | truncated SHA-256 of bitcoin address (stored in `btc_hash` tag) | 10 |
| peer | LN peer pubkey | 3 |

Caps block a single underlying identity from flooding the list by rotating Nostr keys. Only **active, unexpired** vouches count toward the cap — when a vouch expires naturally, the slot is freed automatically. Re-applying with the same Nostr key is cap-neutral (the replaceable d-tag supersedes the old entry).

For utxo-tier the cap is keyed on a 12-byte SHA-256 of the verified bitcoin address, stored in a daemon-internal `["btc_hash", ...]` tag. The coordinator enforces per-address Sybil caps by querying relays live on every proof request — Nostr is the single source of truth, no in-memory cap cache — so the hash on the published event is all the identifier anyone needs. Wallets ignore that tag.

## Split rate-limit buckets

The global request ceiling is split by proof type so peer-tier traffic can't starve chain-anchored traffic:

| Bucket | Methods | Default |
|--------|---------|---------|
| Chain-anchored | channel + utxo | 80 requests / hour |
| Peer | peer | 20 requests / hour |

Per-sender: 5/hour, 1/minute per Nostr pubkey. Applies uniformly to every method.

## Spam resistance — three verification tiers

- **Tier 1 — proof-of-channel** ([details](./PROOF_OF_CHANNEL.md), chain-anchored). LSP proves control of a Lightning node with ≥1 announced channel by signing a challenge with CLN's `signmessage`. Coordinator verifies via `checkmessage`, which requires BOLT-7 gossip membership (chain-anchored through channel funding).
- **Tier 2 — proof-of-UTXO** ([details](./PROOF_OF_UTXO.md), chain-anchored). LSP without an LN node (or with a too-young channel) proves control of an on-chain bitcoin address holding ≥1 unspent output. Coordinator verifies via `bitcoin-cli verifymessage` + `gettxout`. Host also declares an `ln_node_id` (host-declared contact, not verified — first-dial failure invalidates a bad declaration at no cost).
- **Tier 3 — proof-of-peer** ([details](./PROOF_OF_PEER.md), *off by default on mainnet*). LSP with neither channels nor funded UTXOs proves key possession and daemon reachability via a BOLT-8 Noise handshake the coordinator initiates. No chain anchor. Tighter caps and separate rate bucket.

**How verification cascades.** The coordinator only verifies what the host submits. With `proof_multi`, it tries each submitted proof in order and publishes **one vouch at the first tier that verifies**. A host holds at most one active vouch per coordinator (d-tag = host pubkey hex), labeled with the winning tier.

**How wallets filter for spam resistance.** The `l` tag is a NIP-01 single-letter filterable tag, so filtering happens at the **relay layer** before bytes cross the wire. Recommended wallet discovery order:

1. Query `"#l":["channel"]` — tier 1, strongest, get all of them.
2. Add `"#l":["utxo"]` — tier 2, still chain-anchored.
3. Only if user explicitly opts in: `"#l":["peer"]`, capped to a UI-configurable limit to prevent spam flooding the view.

A flood at peer-tier literally cannot contaminate a tier-1 query result.

**Young-peer safety: use multi-method DMs.** A freshly-funded LN channel won't be in the coordinator's BOLT-7 gossip view for minutes to hours after funding confirms. Any LSP that can produce more than one proof method SHOULD send a `proof_multi` DM rather than single-method. The coordinator cascades from channel → utxo → peer and publishes at the first that verifies — so a new operator who just opened their first channel still gets vouched immediately via the UTXO fallback while gossip catches up.

## Coordinator state model

The coordinator holds essentially no state of its own. **Nostr is the single source of truth** for which vouches are active — the daemon queries relays live on every cap check rather than keeping a local cache. This means:

- No "vouch table" to get out of sync with reality.
- Relay partition for minutes, hours, or even days is self-healing: the moment any relay becomes reachable again, the next proof request just works with fresh data. No circuit breaker, no startup blocking window, no manual intervention.
- A proof arriving while zero relays are reachable is rejected with `state_unavailable` rather than risk publishing a vouch without a cap check.

The only durable state files live next to `coordinator.nsec`:

| File | Purpose | Rebuild if lost? |
|---|---|---|
| `last_seen_dm.txt` | High-water mark of DM `created_at` so a restart subscribes `.since(ts)` and replays the offline backlog | No — but only loses the backlog window, not published vouches |
| `processed_events.txt` | Exactly-once dedup set of DM event ids (7-day TTL, atomic writes) | No — worst case is a duplicate confirmation DM on one replayed request |

**Total-loss recovery.** If the daemon's state files (everything except `coordinator.nsec`) are lost — e.g. you're spinning up a second instance on a fresh VPS from just a key backup — pass `--rebuild-from-days <N>` to the `daemon` subcommand. That overrides the persisted `last_seen_dm` and scans the relays backwards N days on this boot. Typical usage: `--rebuild-from-days 7` to match the self-healing envelope below; bounded by `MAX_DM_LOOKBACK_SECS` (60 days). Cap state is always re-derived live from Nostr on every proof, so the only thing recovery mode "rebuilds" is the DM backlog window.

**Offline tolerance.** The effective self-healing window is **7 days** — the maximum age of a DM the daemon will process after coming back online. Three cooperating mechanisms set this bound:

- `PROCESSED_EVENTS_TTL_SECS = 7d` — dedup set of handled event ids, atomically persisted.
- `CHALLENGE_PAST_WINDOW_SECS = 7d` — asymmetric challenge-freshness window: up to +5 min into the future (clock-skew tolerance) and up to 7d into the past (so backlog DMs arriving after restart still validate their proof-of-control against our clock).
- Rate limits (per-sender, global chain/peer buckets) are **skipped for backlog DMs** — they're a real-time anti-flood defense; replaying a week of legitimate backlog in one burst shouldn't trip them.

A coordinator offline up to 7 days comes back, replays every backlog DM it hasn't already responded to, and issues the corresponding vouches — no manual intervention, no host retries needed. Past 7 days, `processed_events` entries start aging out; a replayed DM whose entry has expired could trigger a duplicate confirmation DM (the vouch publish itself is still idempotent via replaceable d-tag), mild annoyance but not dangerous. Vouches themselves carry 14d (mainnet) / 30d (test) NIP-40 expiration — a coordinator offline past that comes back to an empty seed list naturally, every vouch having been purged at relays on its own schedule.

**DM backlog scan clamp.** The `.since()` filter is clamped at **60 days** (`MAX_DM_LOOKBACK_SECS`). Any persisted `last_seen_dm` older than that floor is ignored — we start scanning from `now - 60d` instead of from the stale timestamp. 60d is wider than the 7d functional recovery window on purpose (no risk of cutting off useful recovery), while still bounding wasted decrypt work on stale or adversarial state-file inputs. Any backlog DM past the 7d freshness window still reaches the daemon but auto-rejects at the freshness check before any expensive verification.

## Multiple coordinators

Wallets SHOULD ship hardcoded defaults AND expose an open npub field so users can add custom coordinators. No protocol change needed — just union vouch lists from whichever coordinators the user trusts. A bad coordinator at worst wastes wallet dials; funds are never at this layer.

## CLI tool

The repo includes a Rust CLI for the coordinator and for LSPs requesting vouches:

```
soup-rendezvous init                 generate a Nostr keypair
soup-rendezvous whoami               print pubkey
soup-rendezvous publish-root         post the root discovery thread
soup-rendezvous challenge            generate a proof-of-channel challenge

# coordinator ops
soup-rendezvous vouch                verify an LN node proof and publish a vouch (manual)
soup-rendezvous revoke-vouch         revoke a previously-published vouch
soup-rendezvous list-vouches         list seed entries from the relays
soup-rendezvous daemon               run the auto-verifying coordinator

# LSP-side — request a vouch
soup-rendezvous request-vouch        (host) send a proof-of-channel DM
soup-rendezvous request-vouch-utxo   (host) send a proof-of-UTXO DM
soup-rendezvous request-vouch-peer   (host) send a proof-of-peer DM
soup-rendezvous request-vouch-multi  (host) send one DM with multiple proofs;
                                     coordinator publishes at the best tier that verifies
```

## Integration

See [WALLET_INTEGRATION.md](./WALLET_INTEGRATION.md) for the wallet-side contract: how to filter the seed list by tier, how to read a vouch, how to dial the LSP over LN, and how to merge multiple coordinator lists.

## Multi-network deployment

One binary can serve multiple networks (mainnet / signet / testnet4) via `--config` + `--network`. Each network has its own Nostr identity, CLN RPC socket, bitcoind datadir, and state directory.

`deploy/soup-rendezvous.example.toml` carries a working template. Example:

```toml
relays = ["wss://nos.lol", "wss://relay.damus.io", "..."]
vouch_expiry_days = 30

[networks.signet]
key_file = "/var/lib/soup-rendezvous-signet/coordinator.nsec"
lightning_dir = "/var/lib/cln-signet"
bitcoin_dir = "/var/lib/bitcoind-signet"
min_utxo_balance_sat = 0
allow_peer_verification = true

[networks.mainnet]
key_file = "/var/lib/soup-rendezvous-mainnet/coordinator.nsec"
lightning_dir = "/var/lib/cln-mainnet"
bitcoin_dir = "/var/lib/bitcoind-mainnet"
vouch_expiry_days = 14
min_utxo_balance_sat = 100000
# allow_peer_verification unset → peer-tier disabled
```

Systemd template `soup-rendezvous@.service` runs one instance per network via `soup-rendezvous@mainnet` etc.

## Reference coordinators (live)

| Network | npub |
|---------|------|
| signet | `npub1zgqcy07tv2gqupug3mrufce9nsjccvta6ynawle54wk2ma7vw96s3wxurq` |
| testnet4 | `npub1dh4rzrpttf94pajglfqrvad2lcaqxncurj4p3keaj43vqrsdvw3q8aq8qr` |
| mainnet | `npub103gc9tm8apf56w56mtcw5r5crz84d6hldk06vkmw8ulaht6ddu8qd7vw4j` |

All three are production-active. Peer-tier is off on mainnet by default.
