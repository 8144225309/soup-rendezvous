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
  "#scheme": ["superscalar/v1"],
  "since": <7-days-ago-unix-timestamp>
}]
```

The `since` filter ensures wallets only fetch recent advertisements,
not years of history. Combined with NIP-40 expiration tags on ads,
old factories self-clean from relays automatically.

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

## 2. Checking proof-of-node (vouch verification)

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
["p", "<host-nostr-pubkey>"]
["ln_node_id", "03abc..."]
```
```json
{
  "ln_node_id": "03abc...",
  "channel_count": 12,
  "capacity_sat": "50000000",
  "verified_at": 1776374943
}
```

The wallet checks:
1. Vouch author is a trusted coordinator pubkey (configurable list)
2. Vouch `p` tag matches the advertisement author
3. Optionally: verify the LN node exists in the gossip graph

Display: **Vouched** (green) or **Unvouched** (yellow).

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
| Once (setup) | proof-of-node to coordinator | challenge + signature | private to coordinator |
| Per factory opening | 38100 advertisement | rules + LSP connection info | no |
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

---

## 8. Wallet settings

- **Nostr relay list** — where to browse and publish. Default:
  `["wss://relay.damus.io", "wss://nos.lol"]`. User-editable.
- **Trusted coordinator pubkeys** — whose vouches to trust. Ship
  with the soup-rendezvous coordinator's pubkey.
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
