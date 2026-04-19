# Wallet Integration — soup-rendezvous

This document is the wallet-side contract. Read this if you're building a wallet that consumes the coordinator's seed list of verified LSPs and dials those LSPs over Lightning to do everything else.

## What Nostr gives you (and doesn't)

Nostr in this protocol is a **seed list**. Three event kinds total:

| Kind | Who | What it's for |
|------|-----|---------------|
| 38099 | coordinator | self-describing identity post (so humans can find the coordinator) |
| 38101 | coordinator | one entry per verified LSP — contact pointer, tier, freshness |
| 4 (encrypted) | host ↔ coordinator | proof request DM (host → coord) and confirmation DM (coord → host) |

That's everything on Nostr. Factory parameters, capacity, fees, slot availability, joining, accept/reject, seal, signing — none of that is on Nostr. All of it happens LSP↔wallet directly over Lightning after a wallet reads the seed list and dials the LSP.

## 1. Discovery — reading the seed list

### Hardcode or configure coordinator npubs

Wallets SHOULD:
- Ship a hardcoded default npub for each network (mainnet / signet / testnet4)
- Expose an open "custom coordinator" npub field so users can add their own
- Union the vouch lists across all enabled coordinators

A bad coordinator at worst wastes wallet dials. Funds are never at risk at this layer — the wallet evaluates every factory offer on its own merits over LN before committing to anything.

### Subscribe to vouches, tier-first

Use NIP-01 filters. Walk the tiers strongest-first:

```json
["REQ", "vouches-tier1", {
  "kinds":   [38101],
  "authors": ["<coordinator-pubkey-hex>"],
  "#l":      ["channel"]
}]
```

Then `"#l":["utxo"]` for tier 2. Then — only if the user explicitly opted in to "show all" and with a UI-configurable per-tier cap — `"#l":["peer"]` for tier 3.

Filtering happens at the relay layer. A peer-tier flood cannot contaminate a channel-tier query.

### What a vouch event looks like

Uniform shape across all three tiers — only the `l` tag value differs:

```
["d",          "<host-nostr-pubkey-hex>"]   # parameterized-replaceable address
["p",          "<host-nostr-pubkey-hex>"]   # filterable by host
["ln_node_id", "<ln-pubkey-hex>"]           # the contact — dial this over LN
["l",          "channel" | "utxo" | "peer"] # tier filter
["btc_hash",   "<24-hex>"]                  # utxo-tier ONLY, daemon-internal, wallets ignore
["expiration", "<unix-ts>"]                 # NIP-40, self-cleans
```
```json
{
  "status":       "active",
  "ln_node_id":   "03abc...",
  "ln_addresses": ["host:9735"],   // OPTIONAL — only if host isn't in BOLT-7 gossip
  "verified_at":  1776374943,
  "expires_at":   1778966943
}
```

That's the whole event. ~150–200 bytes.

### Checks every wallet MUST do

For each vouch event:

1. **Author is in your accepted-coordinator list.**
2. **`content.status == "active"`.** Revoked vouches republish with the same d-tag and `"status": "revoked"` — skip those.
3. **`expiration` tag is in the future.** Belt-and-suspenders against relays that don't honor NIP-40; conformant relays should have already dropped expired events.
4. **`ln_node_id` is present and looks like a valid compressed secp256k1 pubkey.**

Checks every wallet SHOULD do:

5. **Dedup by `ln_node_id`.** One underlying LSP may have multiple vouches across tiers (e.g., same LN node vouched under channel-tier AND utxo-tier under different Nostr keys). Collapse to one card.
6. **Rank by tier.** Show channel-tier first, utxo-tier second, peer-tier last (or hide it entirely unless the user opted in).
7. **For channel-tier vouches: confirm the LN node exists in your local BOLT-7 gossip.** Gossip membership is itself the chain-anchor check, free to verify client-side. If gossip disagrees with the vouch's `ln_node_id`, skip.

## 2. What the vouch does NOT tell you

- Factory parameters (scheme, capacity, fee, lifetime)
- Slot availability
- Fee policy
- Member list or join status
- Anything about active factory state

All of that comes from dialing the LSP over LN after you pick one from the seed list.

## 3. Dialing the LSP

Once you have a vouch, you have:

- `ln_node_id` — 33-byte compressed secp256k1 pubkey
- (optional) `ln_addresses` — if the host isn't in BOLT-7 gossip, a list of `host:port`

Connect via BOLT-8 handshake. If no `ln_addresses`, look the node up in your local BOLT-7 gossip for its advertised addresses.

After dial, send whatever LSP protocol messages your wallet and the LSP agree on (factory-list query, join request, accept/reject flow, seal manifest, signing). That's out of scope for this document — it's the LSP protocol, not the coordination protocol.

## 4. Tier-first discovery — spam-resistant ordering

Because `l` is a NIP-01 single-letter tag, filtering happens at the relay layer. A flood of peer-tier vouches literally cannot contaminate a tier-1 query result. Recommended wallet discovery sequence:

1. Query `"#l":["channel"]` → chain-anchored tier 1. Present first.
2. Add `"#l":["utxo"]` → chain-anchored tier 2. Merge into the list.
3. Only if the user explicitly asks for "show all" / "include unverified": query `"#l":["peer"]`, capped client-side to a sensible limit (e.g., 50 entries) so a peer-tier flood can't dominate the view.

Ranking within a tier is the wallet's choice (proximity, capacity from gossip, fee policy from dial, uptime history, etc.).

## 5. Vouch field reference

The unified vouch format publishes only what wallets need to contact the host's LN node. Everything else the coordinator verified is checked and then stripped on purpose to avoid leaking host-side topology / financial info.

| Field | Tier | Role | Required? |
|---|---|---|---|
| `d` tag (host pubkey hex) | all | identity, parameterized-replaceable key | required |
| `p` tag (host pubkey hex) | all | filterable: `"#p":[host]` | required |
| `l` tag (`channel`/`utxo`/`peer`) | all | filterable tier label | required |
| `ln_node_id` (tag + content) | all | the LN pubkey wallets dial | required |
| `ln_addresses` (content) | all | host:port list (only if not in gossip) | optional |
| `expiration` tag + `expires_at` | all | NIP-40 self-cleaning freshness | required |
| `status` (content) | all | `active` or `revoked` | required |
| `verified_at` (content) | all | audit trail | small, kept |
| `btc_hash` (tag) | utxo only | daemon-internal cap key (wallets ignore) | present on utxo |
| `revoked_at` (content) | revoked | timestamp of revocation | present on revokes |

## 6. Handling revocation

Revoked vouches share the same d-tag as the original active vouch, so relays automatically supersede the prior event. Wallets MUST verify `content.status == "active"` before using the contact pointer. A revoke looks like:

```json
{ "status": "revoked", "revoked_at": 1776990000, "expires_at": 1779582000 }
```

Treat `status == "revoked"` identically to "no vouch at all." Revokes carry their own NIP-40 expiration so they self-clean off relays after their window passes.

## 7. Staleness and liveness

The coordinator does NOT probe LSPs for liveness. If an LSP goes offline mid-expiry, the vouch stays up until it naturally expires. Wallets SHOULD:
- Gracefully handle dial failures (can't connect, timeout, node not found in gossip).
- Optionally de-rank hosts that failed recently — purely local state.
- Not treat a missing LSP as an error requiring user interaction; just skip to the next vouch.

The worst case is a wasted dial. No funds are at risk.

## 8. Multiple coordinators — union model

A wallet can read vouches from N coordinators simultaneously. Just send N parallel REQ filters, one per coordinator npub. Union the results, dedup by `ln_node_id` (one LSP may appear in multiple coordinators' lists).

If coordinators disagree (coord A vouches for an LSP at tier-channel, coord B at tier-utxo, coord C has revoked), UI is the wallet's call. Conservative default: show the LSP with the strongest tier any accepted coordinator still attests to; if ANY accepted coordinator has revoked, hide.

## 9. LSP-side — how an LSP gets vouched

Out of scope for wallet integration but useful context. An LSP:

1. Generates a Nostr keypair (their identity in the seed list).
2. Constructs a challenge in the format `soup-rendezvous:proof-of-<tier>:v0:<coordinator-npub>:<16-hex-nonce>:<unix-ts>`.
3. Signs it with their CLN node (`lightning-cli signmessage`) or bitcoind (`bitcoin-cli signmessage`), or — for peer-tier — just declares their LN addresses.
4. Packages the proof(s) into a `proof_multi` DM payload and sends it NIP-44-encrypted to the coordinator's npub.
5. Waits for a confirmation DM (published as kind-4 to the LSP's npub).
6. Before `expires_at`, re-runs the flow to refresh the vouch.

### Multi-method DM (recommended)

If an LSP can produce more than one proof, bundle them:

```json
{
  "type": "proof_multi",
  "proofs": [
    {
      "type": "proof_of_channel",
      "node_id":   "03abc…",
      "zbase":     "d9rzo…",
      "challenge": "soup-rendezvous:proof-of-channel:v0:<coord>:<hex>:<ts>"
    },
    {
      "type": "proof_of_utxo",
      "btc_address":  "bc1q…",
      "signature":    "H+sig…",
      "challenge":    "soup-rendezvous:proof-of-utxo:v0:<coord>:<hex>:<ts>",
      "utxo_txid":    "<64-hex>",
      "utxo_vout":    0,
      "ln_node_id":   "03abc…",
      "ln_addresses": ["host:9735"]
    },
    {
      "type": "proof_of_peer",
      "ln_node_id": "03abc…",
      "addresses":  ["host:9735"],
      "challenge":  "soup-rendezvous:proof-of-peer:v0:<coord>:<hex>:<ts>"
    }
  ]
}
```

Rules:
- `proofs` array is ORDERED — strongest first.
- Coordinator tries each in order and publishes a vouch at the first tier that verifies. Later proofs are not attempted after a success.
- The whole bundle counts as **one** rate-limit hit.
- `ln_node_id` is required for `proof_of_utxo` (it's what wallets dial; not verified by the UTXO proof — host's word).
- `ln_addresses` is optional and only needed if the LSP's LN node isn't in BOLT-7 gossip.

### Success response (coordinator → host DM)

```json
{
  "type":           "vouch_confirmation",
  "vouch_event_id": "<hex-id>",
  "tier_used":      "channel" | "utxo" | "peer",
  "ln_node_id":     "03...",
  "message":        "vouched"
}
```

### Failure

Currently silent — the LSP polls for a published vouch after ~15s. Structured rejection DMs are on the roadmap.

## 10. Subscription summary

```
# Seed list (strongest tier first)
REQ ["kinds":[38101], "authors":[<coord>], "#l":["channel"]]
REQ ["kinds":[38101], "authors":[<coord>], "#l":["utxo"]]
REQ ["kinds":[38101], "authors":[<coord>], "#l":["peer"]]  # opt-in only

# All vouches about a specific LSP Nostr pubkey (for cross-coordinator dedup)
REQ ["kinds":[38101], "#p":[<host-pubkey-hex>]]

# Coordinator root thread (for UI display of coordinator description)
REQ ["kinds":[38099], "authors":[<coord>]]
```

## 11. Reference coordinators (live)

| Network | npub |
|---------|------|
| signet | `npub1zgqcy07tv2gqupug3mrufce9nsjccvta6ynawle54wk2ma7vw96s3wxurq` |
| testnet4 | `npub1dh4rzrpttf94pajglfqrvad2lcaqxncurj4p3keaj43vqrsdvw3q8aq8qr` |
| mainnet | `npub103gc9tm8apf56w56mtcw5r5crz84d6hldk06vkmw8ulaht6ddu8qd7vw4j` |

Peer-tier is disabled by default on mainnet (`allow_peer_verification = false`). To include peer-tier vouches, users must configure a coordinator that enables them or run their own.

## 12. What's NOT on Nostr (important)

Deliberately out of scope and never added to Nostr:

- Factory advertisements (kind 38100 removed — all factory state lives on the LSP's LN node)
- Slot-fill status updates
- Encrypted join requests
- Seal manifests
- Signing ceremony coordination
- LSP version fingerprints (scraping would help attackers find vulnerable versions in bulk)

All of those happen directly LSP↔wallet over LN, where the wallet inspects every detail end-to-end before committing.
