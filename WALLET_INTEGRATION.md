# Wallet & CLN Plugin Integration Guide

How Soup Wallet and the SuperScalar CLN plugin interact with
soup-rendezvous Nostr events to coordinate factory creation.

soup-rendezvous handles everything BEFORE the LN connection exists:
discovery, matchmaking, and the cohort handoff. Once the wallet has
the sealed manifest, it peers with the LSP over Lightning and all
subsequent factory communication (signing, state updates, rotation,
close) flows over the direct LN connection via custommsg 33001.

```
Nostr (soup-rendezvous)     "I want in" — discovery, join, seal
LN connection (custommsg)   signing, nonces, state (direct, private)
LN network                  payments (routed, multi-hop, normal)
```

## Nostr event kinds

| Kind | Name | Visibility | Who publishes |
|------|------|-----------|---------------|
| 38099 | root_thread | public | coordinator |
| 38100 | advertisement | public | host (LSP) |
| 38101 | vouch | public | coordinator |
| 38102 | status_update | public | host (LSP) |
| 38200 | attestation | encrypted (NIP-44) | joiner (wallet user) |
| 38300 | seal | encrypted (NIP-44) | host (LSP) |

All events are signed with BIP-340 Schnorr by the publishing
identity's Nostr keypair.

Kinds 38099, 38100, and 38101 are parameterized-replaceable (NIP-33).
Clients fetch the current set with a single filter per kind; relays
automatically drop superseded versions. No history replay is required
or possible.

---

## 1. Discovery — browsing available factories

### What the wallet does

Subscribe to one or more Nostr relays for factory advertisements:

```json
["REQ", "factories", {
  "kinds": [38100],
  "#scheme": ["superscalar/v1"],
  "since": <7-days-ago-unix-timestamp>
}]
```

The `since` filter ensures wallets only fetch recent advertisements,
not years of history. Combined with NIP-40 expiration tags on ads,
old factories self-clean from relays automatically.

**Wallets MUST reject any ad whose NIP-40 `expiration` tag is more
than 48 hours in the future.** A compliant host refreshes every 1-2
days; an ad dated further out is either misconfigured, abandoned, or
attempting to bypass the freshness check. This is the wallet-side
enforcement of the freshness contract — the coordinator does not
and should not monitor ad expiries, so the check lives here.

To narrow by tags: `"#t": ["europe"]`
To filter by coordinator: `"#e": ["<root-event-id>"]`

### What each advertisement contains

Tags (public, filterable by relays):
```
["d", "<cohort-name>"]              stable factory identifier
["e", "<root-event-id>"]            reply to coordinator root thread
["scheme", "superscalar/v1"]        signing scheme
["t", "europe"]                     discovery tags (free-form)
["min_members", "4"]
["max_members", "8"]
["slots", "3/8"]                    current fill
["expiry", "<unix-timestamp>"]      join window close
["expiration", "<unix-timestamp>"]  NIP-40 auto-delete hint for relays
```

Content (public JSON, the SuperScalar scheme payload):
```json
{
  "lsp_pubkey": "02abc...",
  "lsp_endpoints": ["lsp.example.com:9735"],
  "total_funding_sat": "10000000",
  "client_contribution_sat": "1000000",
  "lsp_liquidity_sat": "2000000",
  "leaf_arity": 2,
  "epoch_count": 30,
  "lifetime_blocks": 4320,
  "dying_period_blocks": 432,
  "lsp_fee_sat": "5000",
  "lsp_fee_ppm": 1000
}
```

### Key fields the wallet must store

When the user decides to join:
- The full advertisement content (the rules)
- `sha256(advertisement content)` as the `rules_hash`
- The advertisement event ID
- The host's Nostr pubkey (for encrypting the attestation)
- `lsp_pubkey` and `lsp_endpoints` (for the LN connection after seal)

---

## 2. Checking proof-of-channel (vouch verification)

Fetch vouches for an advertisement's author:

```json
["REQ", "vouches", {
  "kinds": [38101],
  "authors": ["<coordinator-pubkey>"],
  "#p": ["<advertisement-author-pubkey>"]
}]
```

A vouch event contains:
```
["d",          "<host-nostr-pubkey-hex>"]   # parameterized-replaceable address
["p",          "<host-nostr-pubkey-hex>"]
["ln_node_id", "03abc..."]
["l",          "channel"]                   # filterable proof-type tag
["expiration", "1778966943"]                # NIP-40, 30 days after verified_at
```
```json
{
  "status": "active",
  "verification_source": "ln_channel",
  "ln_node_id": "03abc...",
  "channel_count": 12,
  "capacity_sat": "50000000",
  "verified_at": 1776374943,
  "expires_at": 1778966943
}
```

The `["l", "channel"]` tag lets wallets filter at the relay layer
for just proof-of-channel vouches via a standard NIP-01 filter:
`{kinds:[38101], authors:[<coord>], "#l":["channel"]}`. The coordinator
also publishes `["l", "utxo"]` vouches for hosts who proved an on-chain
UTXO instead of a Lightning channel — see
[PROOF_OF_UTXO.md](./PROOF_OF_UTXO.md). Both are chain-anchored.
`verification_source` in content matches the tag and gives a
human-readable name (`"ln_channel"` or `"btc_utxo"`).

### Three verification paths — one coordinator identity

```
Filter: {kinds:[38101], authors:[<coord>], "#l":["channel"]}
  → hosts who proved an LN node with ≥1 announced channel
  → content.verification_source == "ln_channel"
  → content.ln_node_id is present
  → Sybil floor: cost of opening one LN channel (chain-anchored)

Filter: {kinds:[38101], authors:[<coord>], "#l":["utxo"]}
  → hosts who proved control of an on-chain bitcoin address
  → content.verification_source == "btc_utxo"
  → content.btc_address and content.verified_balance_sat are present
  → Sybil floor: min_utxo_balance_sat (chain-anchored)

Filter: {kinds:[38101], authors:[<coord>], "#l":["peer"]}
  → hosts who completed a BOLT-8 handshake with the coordinator
  → content.verification_source == "ln_peer"
  → content.peer_pubkey and content.peer_addresses are present
  → Sybil floor: cost of a reachable VPS (NOT chain-anchored)

Filter: {kinds:[38101], authors:[<coord>], "#l":["channel","utxo"]}
  → union of both chain-anchored tiers (recommended default)

Filter: {kinds:[38101], authors:[<coord>]}
  → everything including peer-tier (advanced / opt-in)
```

**Wallets SHOULD default to showing only chain-anchored tiers
(`#l:["channel","utxo"]`) and expose peer-tier behind an explicit
"show all" user opt-in.** Peer-tier is the lowest tier with no chain
anchor; treating peer-tier as equivalent to chain-anchored tiers
opens the UI to cheap flooding. Filter or rank it accordingly. See
[PROOF_OF_PEER.md](./PROOF_OF_PEER.md) for the full analysis.

### Tier-first discovery — spam-resistant ordering

Because `l` is a NIP-01 single-letter tag, the filter happens at the
**relay layer**, before any bytes cross the wire. A flood of peer-tier
vouches literally cannot contaminate a tier-1 query result. This is
the primary defense against lower-tier abuse.

Recommended wallet discovery sequence:

1. Query `"#l":["channel"]` → chain-anchored tier 1. Present first.
2. If the user wants more options (or tier-1 is sparse), query
   `"#l":["utxo"]` → chain-anchored tier 2. Merge into the list.
3. Only if the user explicitly asks for "show all / weakest-included",
   query `"#l":["peer"]`.

A wallet that walks the tiers in this order will never show peer-tier
vouches to a user who didn't ask, and will never have its tier-1 view
degraded by a peer-tier flood. Ranking within a tier is the wallet's
choice (gossip capacity, verified balance, age, fee policy, etc.).

### How coordinator verification works (what one vouch means)

The coordinator only verifies **what the host submits in the DM.**
There is no autonomous probing of all three methods.

- Host sends `proof_of_channel` alone → coordinator verifies channel
  only and either publishes a channel-tier vouch or nothing.
- Host sends `proof_of_utxo` alone → utxo-tier only; same rule.
- Host sends `proof_of_peer` alone → peer-tier only; same rule.
- Host sends `proof_multi` (see §7.1a) → coordinator tries each proof
  in the submitted order and **publishes one vouch at the first tier
  that verifies**. Later proofs in the bundle are not attempted after
  a success.

So at any moment a given host has **at most one active vouch under
each coordinator** (d-tag = host pubkey hex, parameterized-replaceable).
Its `l` tag tells you exactly which tier was satisfied. If the host
re-submits a multi-proof DM later and a stronger tier now verifies,
the new vouch supersedes the prior one at the same d-tag.

For a proof-of-utxo vouch, the content has extra fields:
```json
{
  "status":               "active",
  "verification_source":  "btc_utxo",
  "btc_address":          "bc1q...",
  "verified_balance_sat": "150000",
  "utxo_txid":            "<64-hex>",
  "utxo_vout":            0,
  "verified_at":          1776374943,
  "expires_at":           1778966943
}
```

Wallets that want to apply their own additional balance threshold on
top of the coordinator's configured floor can filter on
`verified_balance_sat` client-side.

The wallet checks (all must pass):
1. Vouch author is in the wallet's accepted-coordinator list (user-configurable)
2. Vouch `p` tag matches the advertisement author
3. **`content.status == "active"`** — a coordinator can revoke a
   host by republishing this event with `"status": "revoked"`. Relays
   supersede the prior version via the `d`-tag; wallets that skip
   this check will continue to accept revoked hosts.
4. **NIP-40 `expiration` tag is in the future.** Vouches are issued
   with a bounded lifetime (30 days by default). A host must re-prove
   via `request-vouch` before expiry or the vouch is silently dropped
   by relays. Wallets MUST also enforce client-side for relays that
   don't honor NIP-40.
5. **`vouch.content.ln_node_id == ad.content.lsp_pubkey`.** The vouch
   binds a Nostr identity to one specific LN node pubkey. If the ad
   points at a different LN node than the one the coordinator
   attested, refuse — the ad is either misconfigured or attempting
   to redirect the wallet to an LN node the host does not control.
5a. **SHOULD deduplicate factory listings by the appropriate identifier
    per method.**
    - Channel vouches: dedup by `content.ln_node_id`.
    - UTXO vouches: dedup by `content.btc_address`.
    - Peer vouches: dedup by `content.peer_pubkey`.

    Because an operator can legitimately rotate Nostr keys per
    factory, the same underlying LSP may appear across multiple
    active vouches, each under a different Nostr identity. The
    coordinator caps this to 10 active vouches per LN node / bitcoin
    address (3 per peer pubkey), but wallets still SHOULD dedup
    because those caps are config knobs, not hard protocol invariants.

5b. **SHOULD collapse cross-method vouches for the same host by Nostr
    identity.** If the same Nostr pubkey holds vouches in more than
    one tier (e.g. a channel vouch AND a utxo vouch under the same
    `d`-tag), those are the same operator using different proof
    methods. Present them as one card, prefer the strongest tier's
    data for primary display, and optionally annotate the other
    tiers as additional attestations.

6. **SHOULD rank by tier** when sorting or displaying the factory list.
   Prefer `channel` and `utxo` (both chain-anchored) over `peer` (weak).
   Default wallet behavior SHOULD be to hide peer-tier vouches entirely
   unless the user explicitly opts into a "show all tiers" view — see
   [PROOF_OF_PEER.md](./PROOF_OF_PEER.md).
6. **SHOULD verify the LN node exists in the current BOLT-7 gossip
   graph** and its self-reported `channel_count` / `capacity_sat`
   match what gossip reports. The coordinator already enforces a
   gossip-existence check at vouch time via CLN's `checkmessage`
   (chain-anchored through channel_announcement signatures), so a
   vouched node was real when it was vouched. But vouch records are
   bounded at 30 days, and channels can force-close in between, so
   the wallet verifies the current state against its own live gossip
   rather than relying on the stale snapshot. This check also catches
   self-reported capacity lies — the ad/vouch say "50 BTC total";
   the wallet independently recomputes from gossip.

A revoked vouch looks like:
```json
{
  "status": "revoked",
  "reason": "operator misbehavior",
  "revoked_at": 1776990000
}
```

Display: **Vouched** (green) or **Unvouched** (yellow). Treat
`status == "revoked"` the same as no vouch at all.

### Vouch field reference — what each field is for

Every field in a vouch earns its place under one of three jobs:
**contact** (how to reach the host over LN), **verifiability** (lets
the wallet independently cross-check the coordinator's claim), or
**ranking** (ordering signals for the UI).

| Field | Tier | Role | Stripped if gone? |
|---|---|---|---|
| `d` tag (host pubkey hex) | all | identity + dedup | required |
| `p` tag (host pubkey hex) | all | lets wallets query by host | required |
| `l` tag (`channel`/`utxo`/`peer`) | all | relay-layer tier filter | required |
| `expiration` tag + `expires_at` | all | NIP-40 self-cleaning freshness | required |
| `status` (`active`/`revoked`) | all | revocation | required |
| `verified_at` | all | audit trail | small, keep |
| `ln_node_id` (content + custom tag) | channel | contact + gossip cross-check | **keep — contact** |
| `channel_count` | channel | ranking | droppable — wallet can ask gossip |
| `capacity_sat` | channel | ranking | droppable — wallet can ask gossip |
| `btc_address` (content + custom tag) | utxo | verifiability (`gettxout` cross-check) | keep — chain-anchor proof |
| `utxo_txid` / `utxo_vout` | utxo | verifiability | keep — same reason |
| `verified_balance_sat` | utxo | ranking + wallet-side floor | keep — cheap, useful filter |
| `peer_pubkey` (content + custom tag) | peer | contact | **keep — contact** |
| `peer_addresses` | peer | contact (non-gossip endpoints) | keep if host isn't in LN gossip |
| `features_hex` | peer | ranking | droppable |

### Known gap — utxo-tier vouches do not carry an LN contact

By design, the coordinator verifies that the host controls a specific
bitcoin address and publishes exactly that claim. It does **not**
attest anything about the host's LN node when operating in utxo-tier
mode. A wallet that only reads the utxo-tier vouch has no way to
know where to dial the host over LN.

In the current architecture this is fine: wallets discover LN contact
information from the host's own kind-38100 factory advertisement,
which carries `lsp_pubkey` and the usual LN addresses. The vouch's
job is "this host is real and paid a Sybil cost"; the ad's job is
"here's how to reach me."

If a future wallet design wants to dial hosts directly from the vouch
(skipping the ad), the utxo DM would need to include a host-declared
`ln_node_id` that the coordinator passes through verbatim (no
verification beyond format — the LN-node binding is separate from
the UTXO proof). This change is not implemented today.

Channel-tier vouches do not have this gap: `ln_node_id` is the
chain-anchored proof target, so it's always present. Peer-tier vouches
do not have this gap either: `peer_pubkey` is itself the LN node id.

### Challenge format security

The proof-of-channel challenge uses a structured format with domain
separation to prevent cross-protocol signature replay:

```
soup-rendezvous:proof-of-channel:v0:<coordinator-npub>:<random-hex>:<unix-timestamp>
```

This ensures signatures produced for soup-rendezvous cannot be
replayed against LNURL-auth, Amboss, or any other service that uses
CLN signmessage. The coordinator's npub is embedded in the challenge
so signatures can't be replayed across different coordinators.

See [PROOF_OF_CHANNEL.md](./PROOF_OF_CHANNEL.md) for the full security
model, validation rules, and operator checklist.

---

## 3. Joining — encrypted attestation

1. Wallet generates the attestation payload
2. Encrypts to the host's Nostr pubkey using NIP-44
3. Publishes kind 38200

Tags (public):
```
["e", "<advertisement-event-id>"]
["p", "<host-nostr-pubkey>"]
["scheme", "superscalar/v1"]
["expiry", "<unix-timestamp>"]
```

Content (NIP-44 encrypted to host):
```json
{
  "joiner_cln_pubkey": "03def...",
  "joiner_cln_endpoint": "joiner.example.com:9735",
  "nonce": "a1b2c3d4...",
  "message": "requesting to join, online 18-22 UTC"
}
```

### NIP-44 encryption

TypeScript (nostr-tools):
```typescript
const encrypted = nip44.encrypt(joinerSecretKey, hostPubkey, payloadJson)
```

Rust (nostr crate):
```rust
let encrypted = nip44::encrypt(&secret_key, &host_pubkey, &json, nip44::Version::default())?;
```

---

## 4. Monitoring — watching the factory fill

Subscribe for status updates:
```json
["REQ", "status", {
  "kinds": [38102],
  "#e": ["<advertisement-event-id>"]
}]
```

Status events form a timeline: "1/8 joined", "2/8 joined", ...,
"sealed". The wallet shows this as a live activity feed.

Subscribe for the seal (the trigger to move to LN):
```json
["REQ", "seal", {
  "kinds": [38300],
  "#e": ["<advertisement-event-id>"],
  "#p": ["<my-nostr-pubkey>"]
}]
```

---

## 5. Receiving the seal — the handoff to LN

The seal event is NIP-44 encrypted to the wallet's Nostr pubkey.
Decrypt it:

```typescript
const manifest = JSON.parse(nip44.decrypt(walletSecretKey, hostPubkey, sealEvent.content))
```

### Seal manifest

```json
{
  "advertisement_id": "<event-id>",
  "rules_hash": "<sha256 of advertisement content>",
  "members": [
    {
      "nostr_pubkey": "<hex>",
      "cln_pubkey": "03abc...",
      "cln_endpoint": "host:9735",
      "slot": 0
    }
  ],
  "sealed_at": 1776374943
}
```

### What the wallet does with the seal

1. **Verify rules_hash.** Compute `sha256(stored advertisement content)`
   and compare. Mismatch → refuse, alert user.
2. **Verify own membership.** Own pubkey must appear in the members list.
3. **Extract LN connection info.** The LSP's `lsp_pubkey` and
   `lsp_endpoints` from the advertisement. Each member's `cln_pubkey`
   and `cln_endpoint` from the manifest.
4. **Peer with the LSP over Lightning.** Connect to `lsp_endpoints`
   using standard LN peer connection.
5. **Hand off to the CLN plugin.** Pass the member list and factory
   parameters. The plugin runs the MuSig2 ceremony via custommsg 33001.

**soup-rendezvous is done at this point.** Everything from here
forward — nonce exchange, partial signatures, state updates, factory
rotation, close — flows over the direct LN connection between the
wallet and the LSP. No Nostr, no intermediaries, no routing.

---

## 6. What happens on the LN connection (NOT our layer)

For reference only — this is the CLN plugin's domain:

```
LN connection = direct peer-to-peer encrypted pipe (BOLT-8 Noise)
  - forward secrecy (ephemeral Diffie-Hellman per session)
  - no intermediate nodes see anything
  - no routing, no hops, no fees

custommsg 33001:
  - MuSig2 nonce commitments and reveals
  - partial signature exchange
  - state update proposals and countersignatures
  - factory rotation coordination
  - assisted and unilateral exit signaling
```

This is private between the wallet and the LSP. No outsider can
observe the signing ceremony, construct transactions, or grief with
force closes.

---

## 7. Data the LSP must publish to Nostr

| When | Event kind | Content | Encrypted? |
|------|-----------|---------|-----------|
| Bootstrap, then every ~21 days | 4 (DM to coordinator) | one of proof-of-channel, proof-of-utxo, or proof-of-peer payload — see §7.1 | yes, NIP-44 to coordinator |
| Per factory opening | 38100 advertisement | rules + LSP connection info | no |
| Per factory, every 1–2 days | 38100 re-publish (same d-tag) | same ad with refreshed timestamp | no |
| As joiners arrive | 38102 status_update | slot count, message | no |
| When cohort is full | 38300 seal (one per member) | member manifest | yes, per-member |
| When cohort is full | 38102 status_update | "sealed" | no |

After the seal, the LSP publishes nothing more to Nostr for that
factory. All subsequent communication is over the LN connection.

### Required advertisement fields

```json
{
  "lsp_pubkey": "02...",           // REQUIRED — LN node ID
  "lsp_endpoints": ["host:9735"],  // REQUIRED — how to reach LN node
  "total_funding_sat": "10000000", // REQUIRED
  "client_contribution_sat": "1000000",
  "lsp_liquidity_sat": "2000000",
  "leaf_arity": 2,
  "epoch_count": 30,
  "lifetime_blocks": 4320,
  "dying_period_blocks": 432,
  "lsp_fee_sat": "5000",
  "lsp_fee_ppm": 1000
}
```

### 7.1 LSP bootstrap: requesting a vouch

Before the LSP can publish any advertisements that wallets will accept,
it must get vouched by a coordinator. The flow is one-shot — the LSP
constructs everything itself, sends a single encrypted DM, and the
coordinator validates and publishes the vouch.

**Three verification methods are supported**, each with its own
challenge prefix and payload shape but the same envelope (NIP-44
encrypted kind-4 DM to the coordinator's npub):

| Method | Use when… | Details |
|---|---|---|
| **proof-of-channel** | you run an LN node with ≥1 announced channel (chain-anchored) | see below + [PROOF_OF_CHANNEL.md](./PROOF_OF_CHANNEL.md) |
| **proof-of-utxo** | you don't have channels but do have on-chain bitcoin (chain-anchored) | [PROOF_OF_UTXO.md](./PROOF_OF_UTXO.md) |
| **proof-of-peer** | you have an LN daemon reachable at a public address but no channels or UTXOs (weakest, disabled on mainnet by default) | [PROOF_OF_PEER.md](./PROOF_OF_PEER.md) |

The proof-of-channel example below shows the single-method flow.
Proof-of-UTXO and proof-of-peer follow the same envelope and response
pattern with different payloads — see their dedicated docs for the
per-method request schema.

### 7.1a Multi-method DM (recommended for hosts with multiple proofs)

If the host can produce more than one kind of proof, they SHOULD bundle
them into a single `proof_multi` DM rather than sending one method at
a time. The coordinator tries each in order and publishes a vouch at
the first tier that verifies. One DM, one response. Resilient to
transient coordinator-side gaps (e.g., gossip not yet populated for a
channel-tier proof) because the coordinator automatically falls through
to the next proof.

Payload:

```json
{
  "type": "proof_multi",
  "proofs": [
    {
      "type": "proof_of_channel",
      "node_id":      "03abc…",
      "zbase":        "d9rzo…",
      "challenge":    "soup-rendezvous:proof-of-channel:v0:<coord>:<hex>:<ts>",
      "channels":     12,
      "capacity_sat": "50000000"
    },
    {
      "type": "proof_of_utxo",
      "btc_address": "bc1q…",
      "signature":   "H+sig…",
      "challenge":   "soup-rendezvous:proof-of-utxo:v0:<coord>:<hex>:<ts>",
      "utxo_txid":   "<64-hex>",
      "utxo_vout":   0
    }
  ]
}
```

Rules:
- The `proofs` array is ORDERED. Put the strongest proof first; the
  coordinator tries them in that order.
- Each proof object is the same per-method payload that you'd send as
  a single-method DM, wrapped in an array.
- The whole bundle counts as **one** rate-limit hit (not N).
- Replay cache is keyed on the first proof's challenge.
- Per-method caps still apply individually — if channel-tier is at cap
  but utxo-tier has room, the coordinator falls through and publishes
  at utxo-tier.
- **Only one vouch is published per bundle** — at the first successful
  tier. Subsequent proofs are not attempted once a tier succeeds.

Success response (coordinator → host DM):

```json
{
  "type":           "vouch_confirmation",
  "vouch_event_id": "<hex-id>",
  "tier_used":      "channel" | "utxo" | "peer",
  // plus the per-tier fields (node_id, btc_address, peer_pubkey, etc.)
  "message":        "vouched"
}
```

Failure: coordinator sends no DM in current implementation (same as
single-method); the host polls for the absence of a vouch after ~15s.

Hosts that only have one proof method can still use single-method DMs
(see §7.1) — multi-method is an orchestration convenience, not a
replacement.

### 7.1b The "young peer" scenario — why multi-method matters

A concrete case the protocol is designed to handle gracefully:

> An operator spins up a fresh CLN node, funds and opens a channel, the funding transaction confirms, and within minutes they try to host their first factory. They're doing everything correctly — and fast.

Under single-method proof-of-channel, that operator hits a problem: **the coordinator's gossip view hasn't propagated their new channel yet.** BOLT-7 gossip propagation takes minutes-to-hours. For a brand-new channel, the coordinator's `checkmessage` rejects the proof with `verified=false`, not because the signature is wrong but because our gossip hasn't caught up to their announcement.

Without multi-method, the operator would have to:
1. Try proof-of-channel → get rejected.
2. Guess at the reason (no explicit failure DM yet, tracked as #30).
3. Re-construct the DM as proof-of-UTXO and try again.
4. Possibly wait.

**With multi-method, one DM handles this cleanly.** The operator sends `[proof_of_channel, proof_of_utxo]` in a single `proof_multi` payload. The coordinator:
1. Tries channel → `verified=false` because of the gossip gap.
2. Falls through to utxo → `verifymessage` + `gettxout` succeed.
3. Publishes a utxo-tier vouch immediately.

The operator is live. Their wallet users can join their factory. When gossip catches up over the next minutes-to-hours, the operator re-runs `request-vouch-multi` at refresh time (or immediately if they want to upgrade), the channel tier now succeeds, and the new channel-tier vouch supersedes the utxo-tier one under the same d-tag.

**This is the core reason the protocol treats the three methods as co-equal rather than strictly hierarchical.** A fresh, legitimate, correctly-operating LSP should never be gated out by a transient gossip gap. Any operator who can produce at least one chain-anchored proof should be vouchable.

Recommendation: **any host that can satisfy more than one method SHOULD always use the `proof_multi` DM form.** The overhead is minor, the resilience benefit is real.

**Step A — discover the coordinator's identity.**

Out-of-band (the coordinator's website, README, or a known-good npub
list). The reference coordinators operated from this repo are:

```
signet   (live; channel + utxo + peer)
  npub: npub1zgqcy07tv2gqupug3mrufce9nsjccvta6ynawle54wk2ma7vw96s3wxurq
  hex:  12030479fd6c5020783111b1f138c966259861afba49f5df9a55d95beef8e174

testnet4 (live; channel + utxo + peer)
  npub: npub1dh4rzrpttf94pajglfqrvad2lcaqxncurj4p3keaj43vqrsdvw3q8aq8qr
  hex:  6dea310c2b5a4b50f648fa403675aafe3a034f1c1caa18db3d9562c00e0d63a2

mainnet  (live; channel + utxo, peer disabled)
  npub: npub103gc9tm8apf56w56mtcw5r5crz84d6hldk06vkmw8ulaht6ddu8qd7vw4j
  hex:  7c5182af67e8534d3a9adaf0ea0e98188f56eaff6d9fa65b6e3f3fdbaf4d6f0e
```

Pick the coordinator npub for the network the LSP is operating on.
All three networks are active. On mainnet, peer-tier proofs are
refused (only proof-of-channel and proof-of-UTXO are accepted).

```
relays (any subset reaches the active daemons):
  wss://nos.lol
  wss://relay.damus.io
  wss://relay.primal.net
  wss://relay.nostr.band
  wss://relay.snort.social
  wss://offchain.pub
  wss://nostr.fmt.wiz.biz
```

An LSP integrator SHOULD also fetch the coordinator's root thread to
confirm the npub is live and see any operator notes:

```json
["REQ", "root", {
  "kinds": [38099],
  "authors": ["<coordinator-pubkey-hex>"],
  "#d": ["root"]
}]
```

The root thread is parameterized-replaceable, so exactly one event
comes back per coordinator.

**Step B — construct the challenge.**

```
soup-rendezvous:proof-of-channel:v0:<coordinator-npub>:<16-byte-hex>:<unix-ts>
```

The LSP fills in all fields itself — no pre-coordination with the
coordinator. See [PROOF_OF_CHANNEL.md](./PROOF_OF_CHANNEL.md) for why this
is safe and what each field does.

**Step C — sign with the LSP's CLN node.**

```
$ lightning-cli signmessage "<challenge>"
{
  "signature": "c978…",
  "recid": "00",
  "zbase": "d9rzo78k9u9zds7bi8en…"
}
```

The `zbase` field is what gets sent; the others are informational.

**Step D — build the request payload.**

```json
{
  "type":         "proof_of_channel",
  "node_id":      "03abc…",           // from lightning-cli getinfo
  "zbase":        "d9rzo…",           // from step C
  "challenge":    "soup-rendezvous:proof-of-channel:v0:…",
  "channels":     12,                 // optional, for metadata on the vouch
  "capacity_sat": "50000000"          // optional, string to avoid JSON integer limits
}
```

**Step E — encrypt and send as a kind-4 DM.**

```typescript
// TypeScript (nostr-tools)
const encrypted = nip44.encrypt(lspSecretKey, coordinatorPubkey, JSON.stringify(payload));
const event = {
  kind: 4,
  pubkey: lspPubkeyHex,
  created_at: Math.floor(Date.now() / 1000),
  tags: [["p", coordinatorPubkeyHex]],
  content: encrypted,
};
// sign with LSP nsec and publish to coordinator's relays
```

```rust
// Rust (nostr crate)
let encrypted = nip44::encrypt(
    lsp_keys.secret_key(),
    &coordinator_pubkey,
    &serde_json::to_string(&payload)?,
    nip44::Version::default(),
)?;
let builder = EventBuilder::new(Kind::Custom(4), encrypted)
    .tag(Tag::public_key(coordinator_pubkey));
client.send_event_builder(builder).await?;
```

**Step F — wait for the confirmation DM.**

On success, the coordinator replies with a kind-4 DM encrypted to the
LSP's pubkey. Parse the decrypted content as JSON:

```json
{
  "type":           "vouch_confirmation",
  "vouch_event_id": "<hex-event-id-of-the-38101-vouch>",
  "node_id":        "03abc…",
  "message":        "vouched"
}
```

The LSP should also verify the vouch appeared on relays (fetch
`kinds:[38101], authors:["<coordinator>"], #d:["<lsp-pubkey-hex>"]`).
If the vouch is present and `content.status == "active"`, the LSP is
live.

**On failure, the coordinator sends no DM in the current
implementation.** The LSP should:

1. Wait ~15 seconds after publishing the request DM.
2. Query relays for a vouch addressed to its pubkey. If present and
   active → success; the confirmation DM may have been dropped.
3. If no vouch appears, the request was rejected. Check locally that
   your challenge format, coordinator npub, timestamp freshness (< 5
   min), and CLN signature are all valid, then retry.
4. If you hit the per-sender rate limit (5 requests/hour), back off
   and try again in an hour.

Structured rejection DMs are planned for a future release; when
shipped the LSP will receive an explicit `{"type": "vouch_rejection",
"reason": "..."}` payload instead of having to infer failure from
the absence of a vouch. LSP integrators should build their retry loop
so it tolerates either present-or-future behavior.

**Step G — refresh before 30 days.**

Vouches carry a NIP-40 expiration 30 days out. The LSP must repeat
steps B–F before expiry or the vouch is dropped by relays. A systemd
timer running this every ~21 days is the recommended pattern; see
[README.md](./README.md#freshness-use-it-or-lose-it) for an example
unit file.

### 7.2 Network privacy — LSP-side Tor

The coordinator itself can optionally route its Nostr traffic through a SOCKS5 proxy (see the repo README for operator-side Tor setup). **LSPs and wallets are encouraged to do the same** if they want to keep their infrastructure IP private from relay operators. Npubs are always public — they're how others find you — but the TCP endpoint of your Nostr client does not need to be.

Any Nostr client library that accepts a SOCKS5 proxy works; point it at a local tor daemon (`127.0.0.1:9050` on most Linux distributions). For the reference Rust CLI, pass `--proxy-url 127.0.0.1:9050` or set `SOUP_PROXY_URL` in the environment; any command that touches relays will honor it.

Reminder: Tor hides the TCP endpoint, not the pubkey. The coordinator will still learn your LSP's Nostr identity when you send any proof-of-* DM; it just won't learn your IP.

### 7.3 What the LSP does NOT need to do

- **Not** ask the coordinator to issue a challenge. The LSP builds it.
- **Not** establish any session or handshake beyond the single DM.
- **Not** keep any long-lived connection to the coordinator. One DM
  up, one DM down, done.
- **Not** wait for a vouch to appear on relays if the confirmation DM
  already arrived — the coordinator publishes before replying.

---

## 8. Wallet settings

- **Nostr relay list** — where to browse and publish. Recommended
  default (matches the reference coordinator's publish set):
  ```
  wss://nos.lol
  wss://relay.damus.io
  wss://relay.primal.net
  wss://relay.nostr.band
  wss://relay.snort.social
  wss://offchain.pub
  wss://nostr.fmt.wiz.biz
  ```
  User-editable.
- **Accepted coordinator pubkeys** — the user's chosen allowlist of
  signers whose vouches the wallet will honor. Wallets should ship
  with the reference coordinators preloaded, filtered by the network
  the wallet is currently configured for:
  ```
  signet:   npub1zgqcy07tv2gqupug3mrufce9nsjccvta6ynawle54wk2ma7vw96s3wxurq
  testnet4: npub1dh4rzrpttf94pajglfqrvad2lcaqxncurj4p3keaj43vqrsdvw3q8aq8qr
  mainnet:  npub103gc9tm8apf56w56mtcw5r5crz84d6hldk06vkmw8ulaht6ddu8qd7vw4j
  ```
  Users can add or remove coordinators. A vouch is only honored if
  its `author` pubkey is in this allowlist AND its NIP-40 expiration
  is in the future AND its content.status is "active".
- **Coordination Nostr keypair** — for signing attestations and
  decrypting seals. Generated on first run, stored securely.
  Separate from the CLN node key.

---

## 9. Identity mapping

| Identity | Format | What it's for |
|----------|--------|---------------|
| Wallet Nostr key | BIP-340 x-only 32B | signing attestations, decrypting seals |
| Wallet CLN node key | secp256k1 33B | LN peer connections, factory signing |
| LSP Nostr key | BIP-340 x-only 32B | signing ads, encrypting seals |
| LSP CLN node key | secp256k1 33B | LN connections, factory operations |
| Coordinator Nostr key | BIP-340 x-only 32B | signing vouches |

The Nostr key and CLN key are separate. The CLN key goes inside
encrypted content (attestation, seal). The Nostr key is the author
of public events. Rotating the CLN key doesn't break the Nostr
coordination identity.

---

## 10. Subscription summary

| Purpose | Filter | When |
|---------|--------|------|
| Confirm coordinator is live | `kinds:[38099], authors:["<coordinator>"], #d:["root"]` | at wallet boot, or when user adds a coordinator |
| Browse factories | `kinds:[38100], #scheme:["superscalar/v1"], since:<recent>` | discovery screen |
| Check vouches | `kinds:[38101], authors:["<coordinator>"], #p:["<host>"]` | per listing |
| Factory activity | `kinds:[38102], #e:["<ad-id>"]` | factory detail |
| Wait for seal | `kinds:[38300], #e:["<ad-id>"], #p:["<my-pubkey>"]` | after joining |

---

## 11. Error cases

| Situation | Action |
|-----------|--------|
| No vouch for host | show "unvouched" warning |
| Join not accepted within 24h | timeout, retry or pick another |
| Seal rules_hash mismatch | REFUSE to proceed, do not sign |
| Own pubkey not in seal members | host rejected the join |
| Factory expired or cancelled | remove from active list |
| LN peer connection to LSP fails | retry, check lsp_endpoints |

---

## Reference implementation

The `soup-rendezvous` CLI at
https://github.com/8144225309/soup-rendezvous demonstrates every
step of the Nostr protocol in Rust using `nostr-sdk`. Key files:

- `src/kinds.rs` — event kind constants
- `src/events.rs` — event builders, payload types, tag helpers
- `src/main.rs` — full CLI with 13 commands covering the lifecycle

The wallet and CLN plugin implement the same protocol in their own
languages. After the seal, everything moves to the CLN plugin's
custommsg 33001 over the LN connection.
