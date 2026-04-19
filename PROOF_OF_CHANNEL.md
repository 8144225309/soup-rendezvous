# Proof-of-Channel Verification

How factory hosts prove they control a Lightning node **with at least one announced channel** to get vouched by the soup-rendezvous coordinator.

**Sibling documents:** [PROOF_OF_UTXO.md](./PROOF_OF_UTXO.md) for the on-chain variant (no LN node required), [PROOF_OF_PEER.md](./PROOF_OF_PEER.md) for the weak-tier variant used when neither channels nor UTXOs are available.

## Tier selection

Pick the strongest verification method you can satisfy. The ordering from strongest to weakest:

1. **proof-of-channel** (this document) — use if you have any announced LN channel. Chain-anchored via the channel's funding UTXO.
2. **proof-of-utxo** — use if you don't have LN channels yet but have on-chain bitcoin in a wallet with signmessage support. Chain-anchored via your UTXO.
3. **proof-of-peer** — use as a last resort. Lowest tier, no chain anchor, susceptible to flooding, so wallets may filter peer-tier vouches down or behind an opt-in.

Channel and UTXO are both chain-anchored and co-equal in trust — pick whichever fits your infrastructure. If you have an LN node with channels, proof-of-channel is the natural choice since it doesn't require bitcoin-cli signmessage access.

## Why this exists

Anyone can create a Nostr keypair and ask to be listed in the coordinator's seed list. Proof-of-channel ensures the host actually operates a real Lightning node that's chain-anchored through an announced channel. Spammers would need to fund real on-chain channels to get vouched. Legitimate LSPs already have them.

## Why this is called "proof-of-channel," not "proof-of-node"

The coordinator runs `lightning-cli checkmessage <challenge> <zbase>` **without** passing the pubkey argument. In that mode CLN's `checkmessage`:

1. Recovers the pubkey from the signature (pure ECDSA).
2. Looks that pubkey up in the local **BOLT-7 gossip graph**.
3. Returns `verified: true` **only if** the pubkey is a known gossip node — i.e., has at least one announced channel.

Because a node only appears in the gossip graph after its counterparty's `channel_announcement` has propagated (and `channel_announcement` is signed four ways including both funding-output keys), gossip membership is effectively a chain-anchored statement: *"this pubkey was party to at least one confirmed on-chain channel funding transaction that's still unspent."*

So what we're really verifying is *not* "does this node exist in principle" (which just means "does someone have the private key," a trivial bar) but *"does this node have at least one chain-anchored channel"* — which has a non-trivial on-chain cost floor (~$1-3 per channel open at current mainnet fees). That's the name change.

**Hosts with zero announced channels cannot be vouched under this proof type alone.** They need to open at least one small channel, wait for gossip propagation (usually minutes), and try again — OR include a proof-of-UTXO alongside the channel proof in a multi-method DM (see [WALLET_INTEGRATION.md §9](./WALLET_INTEGRATION.md)) so the coordinator falls through to utxo-tier while gossip catches up.

### Young peer fallback

A freshly-opened channel will not appear in our coordinator's gossip immediately — BOLT-7 propagation is eventually consistent and typically takes minutes to an hour. A host who has just opened their first channel and is legitimately correct-and-fast should include a **proof-of-utxo alongside the channel proof** in a multi-method DM. The coordinator automatically falls through to utxo-tier when channel-tier's gossip check fails. Once gossip catches up, re-running the multi-method request promotes the vouch back to channel-tier. See [WALLET_INTEGRATION.md §7.1b](./WALLET_INTEGRATION.md) for the full rationale.

## One-shot, host-driven

The host does all the work. The coordinator issues nothing and waits for no round-trips — it only validates what arrives.

```
1. Host constructs a challenge using publicly known inputs.
2. Host signs the challenge with its CLN node (signmessage).
3. Host sends the challenge + signature to the coordinator in
   one encrypted kind-4 DM.
4. Coordinator validates, calls checkmessage, and publishes the
   vouch event (kind 38101).
5. Coordinator sends a confirmation DM back. Done.
```

No pre-challenge handshake. No back-and-forth. See [WALLET_INTEGRATION.md §9](./WALLET_INTEGRATION.md) for the exact DM schema.

## Challenge format

```
soup-rendezvous:proof-of-channel:v0:<coordinator-npub>:<random-hex>:<unix-timestamp>
```

Example:
```
soup-rendezvous:proof-of-channel:v0:npub1zgqcy07tv2gqu...s3wxurq:031799dbcc9b8976:1776374943
```

### Field purposes

| Field | Purpose |
|-------|---------|
| `soup-rendezvous` | Domain separator — no other protocol uses this prefix, so the signature cannot be replayed against LNURL-auth, Amboss, or any other service that uses CLN signmessage |
| `proof-of-channel` | Action tag — distinguishes from any future soup-rendezvous message types (proof-of-utxo, proof-of-peer) |
| `v0` | Protocol version — allows format changes without breaking old implementations |
| `<coordinator-npub>` | Binds the signature to a specific coordinator — prevents replay to a different coordinator |
| `<random-hex>` | 16 bytes of cryptographic randomness — prevents pre-computation and prediction |
| `<unix-timestamp>` | Freshness — coordinator rejects challenges where \|now − ts\| > 300 seconds |

### Why host-constructed challenges are safe

A naive design would have the coordinator issue each challenge, but that adds a full round-trip and a per-session cache for no gain. Host-constructed challenges are safe because:

- **Domain separation** means the format is only meaningful to this protocol; a signature produced for soup-rendezvous cannot be misinterpreted by another service.
- **Coordinator binding** (the npub is inside the string) means a signature produced for coordinator A cannot be submitted to coordinator B.
- **Freshness** (timestamp) means a host cannot precompute signatures and stockpile them — the coordinator rejects anything older than five minutes.
- **Uniqueness** (random bytes) means no two challenges collide even if two hosts happen to pick the same timestamp.

What the coordinator does NOT need to remember: which challenges it "issued," because it issued none. It only validates the arriving string against the rules above, plus the gossip-membership check via `checkmessage`.

## Cross-protocol replay resistance

The outer layer (CLN's own `"Lightning Signed Message:"` prefix) protects against raw-signature misuse. The inner layer (our `soup-rendezvous:proof-of-channel:v0:` prefix) protects against application-level misuse by other services that use CLN signmessage.

Known uses of CLN signmessage and why there's no collision:

| Service | Expected message format | Collision risk |
|---------|-------------------------|----------------|
| LNURL-auth | `lnurl:https://…` | None — different prefix |
| Amboss | Amboss-specific format | None — different prefix |
| Lightning Address | service-specific | None — different prefix |
| soup-rendezvous | `soup-rendezvous:proof-of-channel:v0:…` | Only valid for us |

## What CLN signmessage actually does

Under the hood, `lightning-cli signmessage` computes:

```
hash = sha256(sha256("Lightning Signed Message:" + message))
signature = ecdsa_sign_recoverable(hash, node_private_key)
output = zbase32_encode(signature)
```

`checkmessage` (without pubkey argument) reverses it and adds a gossip lookup:

```
hash = sha256(sha256("Lightning Signed Message:" + message))
recovered_pubkey = ecdsa_recover(hash, signature)
verified = (recovered_pubkey is in local gossip graph)
```

The coordinator also cross-checks the recovered pubkey against the `node_id` the host claimed in the request payload. Both must match.

## Security checklist

For the coordinator operator:
- [ ] Reject challenges that don't start with `soup-rendezvous:proof-of-channel:v0:`
- [ ] Reject challenges whose coordinator npub isn't your own
- [ ] Reject challenges where `|now − ts| > 300` seconds
- [ ] Maintain a short-TTL replay cache keyed by `sha256(sender_pubkey || challenge)`
- [ ] Verify `checkmessage` returns `verified: true` (which requires gossip membership) and that the recovered pubkey equals the claimed `node_id`
- [ ] Enforce the per-LN-node active vouch cap before spawning the verification subprocess

For the host being verified:
- [ ] Your node must have ≥1 announced channel and be in gossip before requesting a vouch (use `lightning-cli listnodes <your-id>` on a neighbor to confirm you're visible)
- [ ] The challenge you generate starts with `soup-rendezvous:proof-of-channel:v0:` and contains the coordinator's npub you intend to submit to
- [ ] The timestamp you embed is the current time (within a minute or two)
- [ ] Never `signmessage` a string that doesn't match this exact format — especially not one that was handed to you by a third party
- [ ] Never submit to a coordinator whose npub you don't recognize
