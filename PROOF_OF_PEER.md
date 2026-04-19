# Proof-of-Peer Verification

**This is the weakest of the three verification tiers and is off by default on mainnet.** Before enabling or relying on peer-tier vouches, read this whole document.

**Sibling documents:** [PROOF_OF_CHANNEL.md](./PROOF_OF_CHANNEL.md) for the Lightning-anchored variant, [PROOF_OF_UTXO.md](./PROOF_OF_UTXO.md) for the on-chain UTXO-anchored variant. Both are strictly stronger than proof-of-peer and should be preferred where available.

## Tier selection

Pick the strongest verification method you can satisfy. The ordering from strongest to weakest:

1. **proof-of-channel** — use if you have any announced LN channel.
2. **proof-of-utxo** — use if you don't have LN channels yet but have on-chain bitcoin.
3. **proof-of-peer** (this document) — use only if neither of the above is available.

Peer-tier is a **bootstrap path**, not a steady-state target. If you get vouched via peer and later open a channel, re-prove via proof-of-channel at your next refresh. Your peer-tier vouch will be superseded.

## Why there is no LN feature-bit filter (e.g. "require BLIP-56 support")

It would be natural to ask: why doesn't the coordinator also check that the peer advertises the feature bits the ecosystem needs (BLIP-56 for SuperScalar, etc.)? Answer: **feature compatibility belongs on the factory ad's `scheme` tag, not on the vouch.**

The vouch attests identity — "this Nostr key controls this LN node." What protocols that node can run is a per-factory decision: the same operator might run multiple factories with different schemes over time, and the scheme tag on each kind-38100 advertisement is the right granularity. Wallets subscribe with `"#scheme": ["superscalar/v1"]` and only see ads from hosts whose factory claims to support what the wallet wants. If the host misreports (advertises a scheme they can't actually run), the wallet catches it at join time or signing time and picks a different host.

Pushing feature filtering into the vouch would over-couple identity attestation with capability advertising. The coordinator stays scheme-agnostic by design.

## What this actually proves

Only one thing: the host controls the private key of the LN node_id they claim, *and* their node is reachable at one of the addresses they advertised.

That's it. There is no chain anchor — the host does not need any channels, any on-chain UTXOs, or any funded infrastructure to get a peer-tier vouch. All they need is a running Lightning daemon on a reachable TCP address and the corresponding private key.

## Why this tier exists at all

Proof-of-channel requires an announced channel (real on-chain funding cost). Proof-of-UTXO requires an unspent bitcoin output (real on-chain funding cost). Both have a meaningful Sybil floor denominated in real bitcoin.

Proof-of-peer exists for the narrow case where a host has neither: a brand-new LSP bootstrapping a fresh node, a testnet operator who doesn't want to fund channels for the sake of attestation, or a protocol developer running experiments. The tier is useful but its guarantees are weaker.

The coordinator labels peer-tier vouches with `["l", "peer"]` so wallets can filter at the relay layer. **Wallets SHOULD default to hiding peer-tier vouches** and show them only when the user explicitly opts in to the wider listing.

## Sybil floor: weak

The attacker cost per fresh "identity" is:
- a VPS with a public IP (≈ $5/month, cheaper with IPv6 addresses bound to one host)
- a running LN daemon
- a fresh keypair (free)

None of these are chain-anchored. A single $5 VPS can host many CLN instances on different ports, and IPv6 makes unique public addresses essentially free. At scale, the attacker's cost does not rise in proportion to the number of Sybils.

To compensate, peer-tier vouches are rate-limited more aggressively and capped tighter than chain-anchored tiers:

| Defense | Chain-anchored (channel/utxo) | Peer |
|---|---|---|
| Global rate bucket | 80 requests / hour | **20 requests / hour** |
| Per-identifier active vouch cap | 10 | **3** |

Separate buckets mean peer floods cannot starve legitimate chain-anchored traffic.

## One-shot, coordinator-dials-out

The shape differs from the other two methods: the host doesn't sign anything in the DM. Instead, the coordinator initiates an outbound BOLT-8 peer connection to the host's advertised address. The BOLT-8 Noise handshake authenticates the remote end's key possession cryptographically — if the handshake succeeds, the remote side controls the private key of the pubkey we dialed.

```
1. Host constructs a challenge (for freshness + replay protection).
2. Host sends challenge + ln_node_id + addresses[] in one encrypted
   kind-4 DM. No signature — we don't need signmessage here.
3. Coordinator validates challenge format and timestamp.
4. Coordinator dials lightning-cli connect <pubkey>@<address> for each
   advertised address. First successful handshake wins.
5. Coordinator immediately disconnects (we don't need to stay peered).
6. Coordinator publishes a vouch event (kind 38101, l=peer) and
   sends a confirmation DM.
```

## Challenge format

```
soup-rendezvous:proof-of-peer:v0:<coordinator-npub>:<random-hex>:<unix-timestamp>
```

Field purposes identical to other proof types (see [PROOF_OF_CHANNEL.md](./PROOF_OF_CHANNEL.md#field-purposes)). The challenge is not signed — the BOLT-8 handshake is the proof. The challenge exists so:
- The coordinator can reject stale requests (replay protection).
- The `(sender_pubkey, challenge)` pair feeds the replay cache.

## Request payload

```json
{
  "type":       "proof_of_peer",
  "ln_node_id": "03...",
  "addresses":  ["host:9735", "ipv6.example.com:9735"],
  "challenge":  "soup-rendezvous:proof-of-peer:v0:<coord-npub>:<hex>:<ts>"
}
```

## Coordinator configuration

```toml
# Off by default. Leave off on mainnet unless you've thought carefully
# about wallet-side trust and user expectations.
allow_peer_verification = false

# Tighter cap than channel/utxo because peer has no chain anchor.
max_active_vouches_per_peer = 3
```

Per-network override:

```toml
[networks.signet]
allow_peer_verification = true          # test networks on
max_active_vouches_per_peer = 3

[networks.mainnet]
allow_peer_verification = false         # mainnet off
```

When enabled, the daemon emits a `warn`-level startup log line making it obvious to operators that peer-tier is accepting requests. This is deliberate — if you flip it on accidentally, the log should scream.

## Coordinator checks

In order (cheap first):

1. `allow_peer_verification` is `true` for this coordinator instance. If not, reject immediately with `peer_verification_disabled`.
2. Rate limit — peer bucket (20/hour) and per-sender (5/hour, 1/minute).
3. Challenge has the right prefix, our npub, and the timestamp is within ±5 minutes.
4. Replay cache: `(sender, challenge)` not seen in the last 10 minutes.
5. **Per-peer-pubkey cap**: at most 3 active peer-tier vouches per LN node pubkey.
6. `addresses` array is non-empty.
7. `lightning-cli connect <node_id>@<address>` succeeds against at least one advertised address.
8. Publish vouch event with `["l", "peer"]` tag (unified format — see below).

## What the vouch contains

Identical shape as channel and utxo vouches — only the `l` tag value differs:

```
["d",          "<host-nostr-pubkey-hex>"]
["p",          "<host-nostr-pubkey-hex>"]
["ln_node_id", "<ln-node-id-hex>"]
["l",          "peer"]
["expiration", "<unix-ts>"]
```

```json
{
  "status":       "active",
  "ln_node_id":   "03...",
  "ln_addresses": ["host:9735", "ipv6.example.com:9735"],
  "verified_at":  1776374943,
  "expires_at":   1778966943
}
```

For peer-tier the `ln_node_id` IS the verified peer pubkey (the BOLT-8 handshake confirms key possession). `ln_addresses` is included because peer-tier hosts may not be in BOLT-7 gossip — wallets need addresses to dial.

The handshake observes feature bits during BOLT-1 init exchange but the bits are not republished — wallets re-observe them on first dial. Same rationale for everything else: the vouch is a contact pointer, not a profile.

See [WALLET_INTEGRATION.md §2](./WALLET_INTEGRATION.md) for the full unified field reference and trust model.

## Wallet-side recommendation

**Default behavior: hide peer-tier vouches from the main listing.** Show them only when the user explicitly opts in to "advanced" or "show all" view. A wallet that treats peer-tier vouches as equal to chain-anchored ones opens itself up to UI eclipse by cheap sybils.

Filtering at the relay layer:
```
# Show only chain-anchored
{kinds:[38101], authors:[<coord>], "#l":["channel","utxo"]}

# Show everything (advanced)
{kinds:[38101], authors:[<coord>], "#l":["channel","utxo","peer"]}
```

## Security checklist

For the coordinator operator:
- [ ] Keep `allow_peer_verification = false` on mainnet unless you have a concrete reason otherwise
- [ ] Review the warn-level startup log when the coordinator starts — confirm peer verification is in the expected state for each network
- [ ] `max_active_vouches_per_peer` stays low (default 3 is sensible)
- [ ] Rate-limit buckets are kept separate (channel/utxo vs peer)

For the host being verified:
- [ ] Your LN daemon must be reachable at one of the advertised addresses (coordinator will dial)
- [ ] The coordinator's outbound IP will appear in your LN node's peer log briefly — expected behavior
- [ ] Rotating your LN node key does not carry a peer-tier vouch with you; re-request
- [ ] Don't use peer-tier where channel or UTXO proofs are available — your vouch will be weaker and many wallets will filter it out

## Why we don't accept a signmessage-only path

A few other systems verify LN nodes with CLN's `signmessage` without the gossip check — i.e., just cryptographic proof of key possession. We deliberately don't do this: it's a strictly weaker form of peer-connect (no address reachability, no daemon liveness), and offers zero Sybil resistance since key generation is free. If you have *some* address reachable, use peer. If you don't, use UTXO or channel. There's no use case where signmessage-only would be better than the three tiers we support.
