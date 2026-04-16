# Wallet & CLN Plugin Integration Guide

How Soup Wallet and the SuperScalar CLN plugin interact with
soup-rendezvous Nostr events to coordinate factory creation,
from discovery through signing ceremony.

## Nostr event kinds

| Kind | Name | Visibility | Who publishes |
|------|------|-----------|---------------|
| 38100 | advertisement | public | host (LSP) |
| 38101 | vouch | public | coordinator |
| 38102 | status_update | public | host (LSP) |
| 38200 | attestation | encrypted (NIP-44) | joiner (wallet user) |
| 38300 | seal | encrypted (NIP-44) | host (LSP) |

All events are signed with BIP-340 Schnorr by the publishing
identity's Nostr keypair.

---

## 1. Discovery — browsing available factories

### What the wallet does

Subscribe to one or more Nostr relays for factory advertisements:

```json
["REQ", "factories", {
  "kinds": [38100],
  "#scheme": ["superscalar/v1"]
}]
```

To narrow by region or preference, add tag filters:
```json
"#t": ["europe"],
"authors": ["<known-coordinator-pubkey>"]
```

To see only advertisements from a specific coordinator's root
thread, filter by the root event reference:
```json
"#e": ["<root-event-id>"]
```

### What each advertisement contains

Tags (public, filterable by relays):
```
["d", "<cohort-name>"]              stable factory identifier
["e", "<root-event-id>"]            reply to coordinator root thread
["scheme", "superscalar/v1"]        signing scheme
["t", "europe"]                     discovery tags (free-form)
["min_members", "4"]
["max_members", "8"]
["slots", "3/8"]                    current fill (updated via replaceable event)
["expiry", "<unix-timestamp>"]      join window close
```

Content (public JSON, the SuperScalar scheme payload):
```json
{
  "lsp_pubkey": "02abc...",
  "lsp_endpoints": ["lsp.example.com:9735"],
  "lsp_nostr_pubkey": "<x-only hex>",
  "lsp_nostr_relays": ["wss://relay1.example", "wss://relay2.example"],
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

### Key fields the wallet must extract and store

- `lsp_pubkey` — the LSP's Lightning node identity (33-byte secp256k1
  compressed). Used to connect over BOLT-8 for the ceremony.
- `lsp_endpoints` — host:port to reach the LSP's Lightning node.
- `lsp_nostr_pubkey` — the LSP's Nostr identity for post-cohort
  encrypted communication. The wallet encrypts attestations to this key.
- `lsp_nostr_relays` — relay URLs the LSP monitors. The wallet should
  publish attestations and subscribe for seals on these relays.
- `event.pubkey` — the Nostr pubkey that signed the advertisement.
  This may or may not be the same as `lsp_nostr_pubkey` (the LSP might
  use a separate coordinator identity for advertisements).

### Storing the rules locally

When the user decides to join a factory, the wallet must store the
complete advertisement content locally. This is the rule set the wallet
will enforce at signing time. Specifically, store:

- The full advertisement event (raw JSON)
- `sha256(advertisement event content)` as the `rules_hash`
- The `event.id` (the Nostr event ID) for reference

The `rules_hash` is the load-bearing security property: at ceremony
time, the wallet verifies that the factory parameters the LSP proposes
match this hash. If they don't match, the wallet refuses to sign.

---

## 2. Checking proof-of-node (vouch verification)

### What the wallet does

Before showing an advertisement to the user (or before auto-joining),
check whether the host has been vouched by a trusted coordinator.

Fetch vouches for the advertisement's author:

```json
["REQ", "vouches", {
  "kinds": [38101],
  "authors": ["<coordinator-pubkey>"],
  "#p": ["<advertisement-author-pubkey>"]
}]
```

### What a vouch event contains

Tags:
```
["p", "<host-nostr-pubkey>"]        the vouched host
["ln_node_id", "03abc..."]          the verified LN node
```

Content (public JSON):
```json
{
  "ln_node_id": "03abc...",
  "channel_count": 12,
  "capacity_sat": "50000000",
  "verified_at": 1776374943
}
```

### How the wallet verifies the vouch is legitimate

1. The vouch event's `pubkey` (author) must be a coordinator the
   wallet trusts. The wallet ships with a list of known coordinator
   pubkeys (configurable in settings, like DNS seeders).

2. The vouch event's `p` tag must match the advertisement's author.

3. The `ln_node_id` in the vouch content is the LN node that proved
   itself. The wallet can optionally query the LN gossip graph (via
   its own CLN node or a public explorer) to verify this node exists,
   has the claimed channels/capacity, and is reachable.

### What proof-of-node looks like under the hood

The vouch exists because the host went through this flow:

1. Coordinator generated a random challenge:
   `soup-rendezvous-challenge:<random-hex>:<unix-timestamp>`

2. Host signed the challenge with their CLN node:
   `lightning-cli signmessage "<challenge>"` → produces a `zbase`
   signature (recoverable ECDSA over secp256k1, zbase32-encoded).

3. Coordinator verified via their own CLN node:
   `lightning-cli checkmessage "<challenge>" "<zbase>"` → returns
   `{"verified": true, "pubkey": "03abc..."}` where the recovered
   pubkey matches the host's claimed node_id.

4. Coordinator published the vouch event (kind 38101) attesting
   the verification.

The wallet doesn't need to repeat this verification. The wallet
trusts the coordinator's vouch signature (the coordinator's BIP-340
Nostr signature on the vouch event proves the coordinator authored
it). The only thing the wallet decides is whether it trusts the
coordinator.

### What the wallet should display

When showing a factory advertisement:

- **Vouched** (green) — a trusted coordinator published a vouch for
  this host, with the verified LN node's channel count and capacity.
- **Unvouched** (yellow/gray) — no vouch found from any trusted
  coordinator. The user can still join but should understand the host
  hasn't proved control of an LN node.

---

## 3. Joining a factory — publishing an encrypted attestation

### What the wallet does

1. Fetch the advertisement event to get the host's Nostr pubkey.
2. Build the attestation payload (the joiner's CLN node info).
3. Encrypt the payload to the host's Nostr pubkey using NIP-44.
4. Publish a kind 38200 event to the relays the LSP monitors.

### Attestation event structure

Tags (public — relays can filter, anyone can see that *someone*
attested to *this* factory, but not who or what they said):
```
["e", "<advertisement-event-id>"]   which factory
["p", "<host-nostr-pubkey>"]        so the host's relay filters catch it
["scheme", "superscalar/v1"]
["expiry", "<unix-timestamp>"]      auto-release if not accepted
```

Content (NIP-44 encrypted to host's Nostr pubkey):
```json
{
  "joiner_cln_pubkey": "03def...",
  "joiner_cln_endpoint": "joiner.example.com:9735",
  "joiner_nostr_relays": ["wss://relay1.example"],
  "nonce": "a1b2c3d4e5f6...",
  "message": "I'd like to join, online 18-22 UTC daily"
}
```

### NIP-44 encryption (how to do it)

NIP-44 uses secp256k1 ECDH to derive a shared secret between the
sender and receiver, then encrypts with ChaCha20-Poly1305.

In TypeScript (using @noble/ciphers and @noble/curves):
```typescript
import { nip44 } from 'nostr-tools'

const encrypted = nip44.encrypt(
  joinerSecretKey,    // Uint8Array, 32 bytes
  hostPubkey,         // string, x-only hex
  payloadJson         // string
)
```

In Rust (using the nostr crate with nip44 feature):
```rust
use nostr::nips::nip44;

let encrypted = nip44::encrypt(
    &joiner_secret_key,
    &host_public_key,
    &payload_json,
    nip44::Version::default(),
)?;
```

The encrypted string goes into the event's `content` field. Only the
holder of the host's Nostr secret key can decrypt it.

### What the wallet stores after attesting

- The attestation event ID (for tracking)
- The advertisement event ID (which factory)
- The rules_hash (sha256 of the advertisement content)
- The host's Nostr pubkey (for decrypting the future seal)
- The factory parameters (from the advertisement content)
- Subscription: subscribe for kind 38300 (seal) events referencing
  the advertisement event ID, to get notified when the cohort is
  sealed

---

## 4. Monitoring — watching the factory fill up

### Status updates (kind 38102)

Subscribe for status updates on a factory:
```json
["REQ", "status", {
  "kinds": [38102],
  "#e": ["<advertisement-event-id>"]
}]
```

Each status event has:

Tags:
```
["e", "<advertisement-event-id>"]
["status", "filling"]              or "full", "sealed", "expired", "cancelled"
["slots", "5/8"]
["scheme", "superscalar/v1"]
```

Content (public JSON):
```json
{
  "message": "5 of 8 slots filled, 3 days left to join",
  "accepted_count": 5,
  "max_members": 8
}
```

The wallet can show a live feed of factory activity. Status events
are regular (not replaceable) so they form a timeline. The most
recent one has the current state.

### Monitoring for the seal

Subscribe for the seal:
```json
["REQ", "seal", {
  "kinds": [38300],
  "#e": ["<advertisement-event-id>"]
}]
```

When a seal event arrives, the wallet decrypts it (NIP-44, using the
wallet's Nostr secret key) and extracts the cohort manifest. This is
the trigger to start the signing ceremony.

---

## 5. Receiving the seal — the handoff to ceremony

### Decrypting the seal

The seal event's content is NIP-44 encrypted specifically to the
wallet's Nostr pubkey (the host publishes one seal event per member).

```typescript
const manifest = JSON.parse(
  nip44.decrypt(walletSecretKey, hostPubkey, sealEvent.content)
)
```

### Seal manifest structure

```json
{
  "advertisement_id": "<event-id>",
  "rules_hash": "<sha256 of advertisement content>",
  "members": [
    {
      "nostr_pubkey": "<x-only hex>",
      "cln_pubkey": "03abc...",
      "cln_endpoint": "member1.example.com:9735",
      "slot": 0
    },
    {
      "nostr_pubkey": "<x-only hex>",
      "cln_pubkey": "03def...",
      "cln_endpoint": "member2.example.com:9735",
      "slot": 1
    }
  ],
  "sealed_at": 1776374943
}
```

### What the wallet does with the seal

1. **Verify the rules_hash.** Compute `sha256(stored advertisement content)`
   and compare to `manifest.rules_hash`. If they don't match, the host
   may have changed the rules after the wallet joined — refuse to
   proceed.

2. **Verify membership.** Check that the wallet's own Nostr pubkey
   appears in the `members` list.

3. **Extract CLN connection info.** For each member, note their
   `cln_pubkey` and `cln_endpoint`. The LSP's CLN connection info
   is in the original advertisement's `lsp_pubkey` and `lsp_endpoints`.

4. **Hand off to the CLN plugin.** Pass the member list and factory
   parameters to the CLN plugin, which initiates the MuSig2 ceremony
   via bLIP-56 over BOLT-8 peer messaging.

---

## 6. The MuSig2 ceremony — what happens after the seal

Two paths, depending on architecture choice:

### Path A: ceremony over BOLT-8 (traditional)

The CLN plugin receives the sealed manifest from the wallet and
connects to the LSP and other members over Lightning peer messaging.
The MuSig2 nonce exchange and partial signature exchange happen over
the existing BOLT-8 encrypted authenticated channels. The
soup-rendezvous protocol is completely uninvolved at this point.

This is the natural path if all participants are running CLN nodes
and are reachable over Lightning.

### Path B: ceremony over Nostr (alternative)

If participants are behind NAT or otherwise unreachable over
Lightning, the MuSig2 ceremony can run over Nostr NIP-44 encrypted
DMs. Star topology with the LSP at the center:

Round 1 — nonce commitment:
- LSP sends each signer a DM: "generate nonce, send commitment"
- Each signer sends nonce commitment via NIP-44 DM to LSP

Round 2 — reveal and partial signature:
- LSP sends each signer: "all commitments, compute partial sig"
- Each signer sends partial signature via NIP-44 DM to LSP

Completion:
- LSP aggregates, sends final signature to all via NIP-44 DM

The Nostr DMs use the same relays from `lsp_nostr_relays` in the
advertisement. Each message is NIP-44 encrypted between the signer
and the LSP — other signers cannot see each other's nonces.

### What the CLN plugin must do at signing time

Regardless of which path the ceremony takes, the CLN plugin must:

1. **Commit the rules_hash inside the factory metadata.** The
   `rules_hash` (sha256 of the advertisement content) must be
   included in the data that all participants MuSig2-sign. This is
   the cryptographic binding that closes the rule-substitution
   attack: every signer independently verifies the rules_hash
   matches what they agreed to.

2. **Verify factory parameters match the rules.** Before signing,
   check that the proposed factory's funding amount, capacity split,
   leaf arity, lifetime, and fee parameters match the values from
   the stored advertisement.

3. **Refuse to sign on mismatch.** If any parameter doesn't match
   the stored rules, the plugin must refuse to produce a partial
   signature and report the mismatch to the wallet.

---

## 7. Post-factory communication over Nostr

After the factory is live on-chain, the LSP and members communicate
over Nostr for routine operations. All messages use the
`lsp_nostr_relays` from the advertisement.

### LSP → all members (public broadcast)

The LSP signs a regular Nostr event and posts to its relays.
Wallets subscribe by the LSP's Nostr pubkey:

```json
["REQ", "lsp-broadcasts", {
  "authors": ["<lsp-nostr-pubkey>"],
  "since": <last-check-timestamp>
}]
```

Examples:
- "Factory state update scheduled for tomorrow 14:00 UTC"
- "Factory expiring in 7 days, migration factory posted"
- "New factory advertisement for cohort migration"

### LSP → specific member (encrypted DM)

NIP-44 encrypted to the member's Nostr pubkey:
- "Your leaf needs rebalancing, please come online"
- "Here's a state transaction to countersign" (with the actual tx)
- "Assisted exit initiated, here are the closing details"

### Member → LSP (encrypted DM)

NIP-44 encrypted to the LSP's Nostr pubkey:
- "I'm online and ready to sign"
- "Here's my partial signature for the state update"
- "I want to exit the factory"

### Verifying message authenticity

Every Nostr event has a BIP-340 Schnorr signature from its author.
When receiving a message, the wallet:

1. Verifies the BIP-340 signature on the event (standard Nostr
   verification, handled by the Nostr client library).
2. Checks the author pubkey against the seal manifest. If the
   message is from the LSP, `event.pubkey` must match the
   `lsp_nostr_pubkey` from the advertisement. If from a member,
   `event.pubkey` must appear in `manifest.members[].nostr_pubkey`.
3. Decrypts the content (NIP-44) with the wallet's secret key.

A message from an unknown pubkey is discarded — it's not from a
cohort participant.

### How the LSP proves it controls the LN node in messages

The LSP's advertisement contains both `lsp_pubkey` (LN node ID)
and `lsp_nostr_pubkey` (Nostr identity). The coordinator's vouch
event cryptographically binds `lsp_nostr_pubkey` to a verified LN
node. So the chain of trust is:

```
LN node private key
  → signmessage(challenge) → zbase signature
  → coordinator calls checkmessage → verified=true
  → coordinator publishes vouch event (kind 38101)
    binding host_nostr_pubkey to ln_node_id
  → coordinator signs the vouch with BIP-340

wallet checks:
  vouch.pubkey == trusted coordinator?  ✓
  vouch.p_tag == advertisement.pubkey?  ✓
  vouch.ln_node_id exists in LN graph? ✓ (optional)
  therefore: this Nostr identity controls that LN node
```

Any subsequent message signed by that Nostr pubkey inherits the
proof. The wallet doesn't need to re-verify the LN node for every
message — the vouch is durable. It only needs to verify the BIP-340
signature on each event (which the Nostr client library does
automatically).

---

## 8. Data the LSP must publish to Nostr

Summary of everything the LSP needs to put on Nostr for the full
lifecycle to work:

### Before any factory

- A Nostr keypair (the LSP's coordination identity)
- Proof-of-node: contact the coordinator, sign a challenge with the
  CLN node, receive a vouch event

### Per factory

| When | Event kind | Content | Encrypted? |
|------|-----------|---------|-----------|
| Opening | 38100 advertisement | scheme payload with all factory params + LSP contact info | no |
| As joiners arrive | 38102 status_update | slot count, status message | no |
| On acceptance | NIP-44 DM to joiner | "you're accepted, slot N" | yes |
| When full | 38300 seal (one per member) | full manifest with all member CLN info | yes, per-member |
| When full | 38102 status_update | "sealed, ceremony can begin" | no |
| During ceremony (path B) | NIP-44 DMs | nonce requests, commitments, partial sigs | yes |
| Ongoing | regular events | broadcast announcements | no |
| Ongoing | NIP-44 DMs | state updates, rebalance requests | yes |

### LSP advertisement content — required fields

These fields must be present in the advertisement content for the
wallet to function:

```json
{
  "lsp_pubkey": "02...",           // REQUIRED — 33-byte LN node ID
  "lsp_endpoints": ["host:9735"],  // REQUIRED — how to reach LN node
  "lsp_nostr_pubkey": "abc...",    // REQUIRED — x-only, for NIP-44 encryption
  "lsp_nostr_relays": ["wss://"],  // REQUIRED — where to publish/subscribe
  "total_funding_sat": "10000000", // REQUIRED — total factory UTXO
  "client_contribution_sat": "1000000", // REQUIRED
  "lsp_liquidity_sat": "2000000",  // REQUIRED
  "leaf_arity": 2,                 // REQUIRED
  "epoch_count": 30,               // REQUIRED
  "lifetime_blocks": 4320,         // REQUIRED
  "dying_period_blocks": 432,      // REQUIRED
  "lsp_fee_sat": "5000",           // REQUIRED
  "lsp_fee_ppm": 1000              // REQUIRED
}
```

---

## 9. Wallet settings

The wallet needs these configurable values:

- **Nostr relay list** — where to subscribe for advertisements and
  publish attestations. Default: `["wss://relay.damus.io", "wss://nos.lol"]`.
  Should be user-editable.

- **Trusted coordinator pubkeys** — whose vouches to trust. Default:
  ship with the soup-rendezvous coordinator's pubkey. User can add
  more.

- **Coordination identity** — the wallet's Nostr keypair for signing
  events and decrypting incoming messages. Generated on first run,
  stored securely alongside other wallet keys. Separate from the CLN
  node key.

- **Auto-join preferences** (optional) — scheme filter, tag filters,
  min/max capacity, fee limits. If set, the wallet can auto-join
  matching factories without user interaction.

---

## 10. Identity mapping

| Identity | Format | Where it lives | What it's for |
|----------|--------|----------------|---------------|
| Wallet Nostr key | BIP-340 x-only (32 bytes) | wallet keystore | signing Nostr events, NIP-44 encryption |
| CLN node key | secp256k1 compressed (33 bytes) | CLN node | BOLT-8 connections, LN operations |
| LSP Nostr key | BIP-340 x-only (32 bytes) | LSP keystore | signing events, NIP-44 encryption |
| LSP CLN node key | secp256k1 compressed (33 bytes) | LSP CLN node | factory operations, LN connections |
| Coordinator Nostr key | BIP-340 x-only (32 bytes) | coordinator keystore | signing vouches |

The wallet Nostr key and CLN node key are separate. The Nostr key
goes in the event metadata (author of attestations). The CLN key
goes inside the encrypted attestation content (so the LSP knows
how to reach the wallet's Lightning node). This separation means:

- Rotating the CLN node key doesn't break the Nostr coordination
  identity
- Using a fresh Nostr key per factory prevents cross-factory
  correlation
- The coordinator never needs to know the CLN key — it only sees
  the Nostr key
- The relay never sees the CLN key — it's inside NIP-44 encrypted
  content

---

## 11. Subscription summary for the wallet

The wallet maintains these Nostr subscriptions:

| Purpose | Filter | When |
|---------|--------|------|
| Browse factories | `kinds:[38100], #scheme:["superscalar/v1"]` | discovery screen |
| Check vouches | `kinds:[38101], authors:["<coordinator>"], #p:["<host>"]` | per factory listing |
| Factory activity | `kinds:[38102], #e:["<ad-id>"]` | factory detail view |
| Wait for seal | `kinds:[38300], #e:["<ad-id>"], #p:["<my-pubkey>"]` | after attesting |
| LSP broadcasts | `authors:["<lsp-nostr-pubkey>"]` | after joining |
| LSP DMs | `kinds:[4,1059], #p:["<my-pubkey>"]` | ongoing |

---

## 12. Error cases and what to do

| Situation | What the wallet does |
|-----------|---------------------|
| No vouch found for host | Show "unvouched" warning, let user decide |
| Attestation not accepted within 24h | Show timeout, offer to retry or pick another factory |
| Seal rules_hash doesn't match stored rules | REFUSE to proceed, alert user, do not sign |
| CLN node unreachable for ceremony | Retry, or fall back to Nostr-based ceremony (path B) |
| Seal received but user's pubkey not in members | Host rejected the join, show "not accepted" |
| Factory status is "cancelled" or "expired" | Remove from active list, don't attest |
| Multiple seals for same factory | Use the most recent by created_at |
| Relay doesn't return events | Try other relays in the configured list |

---

## Reference implementation

The `soup-rendezvous` CLI tool at
https://github.com/8144225309/soup-rendezvous implements all of the
above in Rust using the `nostr-sdk` crate. Key files:

- `src/kinds.rs` — event kind constants
- `src/events.rs` — event builders, payload types, tag helpers
- `src/main.rs` — full CLI demonstrating every flow

The wallet and CLN plugin should implement the same protocol in
their own languages using standard Nostr client libraries
(`nostr-tools` for TypeScript, `nostr-sdk` for Rust, etc).
