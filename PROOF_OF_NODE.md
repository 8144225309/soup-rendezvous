# Proof-of-Node Verification

How factory hosts prove they control a Lightning node to get vouched
by the soup-rendezvous coordinator.

## Why this exists

Anyone can create a Nostr keypair and post a factory advertisement.
Proof-of-node ensures the host actually operates a real Lightning node
with funded channels. Spammers need real infrastructure to get vouched.
Legitimate LSPs already have one.

## Challenge format

The challenge is a structured string with a domain separator that
prevents cross-protocol signature replay:

```
soup-rendezvous:proof-of-node:v0:<coordinator-npub>:<random-hex>:<unix-timestamp>
```

Example:
```
soup-rendezvous:proof-of-node:v0:npub1zgqcy07tv2gqu...s3wxurq:031799dbcc9b8976:1776374943
```

### Field purposes

| Field | Purpose |
|-------|---------|
| `soup-rendezvous` | Domain separator — no other protocol uses this prefix, so the signature cannot be replayed against LNURL-auth, Amboss, or any other service that uses CLN signmessage |
| `proof-of-node` | Action tag — distinguishes from any future soup-rendezvous message types |
| `v0` | Protocol version — allows format changes without breaking old implementations |
| `<coordinator-npub>` | Binds the signature to a specific coordinator — prevents replay to a different coordinator |
| `<random-hex>` | 16 bytes of cryptographic randomness — prevents pre-computation and prediction |
| `<unix-timestamp>` | Expiry — coordinator rejects challenges older than 5 minutes |

### Why this format prevents abuse

**Cross-protocol replay attack:** A malicious coordinator could try
to craft a challenge that doubles as a valid signed message for
another service (e.g., LNURL-auth). The structured format prevents
this — no other protocol accepts messages starting with
`soup-rendezvous:proof-of-node:v0:`. If a coordinator sends a message
that doesn't match this exact format, the signing wallet must refuse.

**Cross-coordinator replay attack:** A malicious party could try to
take a signature produced for coordinator A and submit it to
coordinator B. The coordinator's own npub is embedded in the
challenge, so coordinator B rejects it (the npub doesn't match).

**Pre-computation attack:** A malicious party could try to
pre-generate challenges and harvest signatures over time. The random
hex and timestamp make each challenge unique and short-lived.

## The verification flow

### Step 1: coordinator generates a challenge

```
$ soup-rendezvous challenge
challenge: soup-rendezvous:proof-of-node:v0:npub1zgq...wxurq:a1b2c3d4e5f6:1776374943

Give this to the host. They sign it with their CLN node.
```

The coordinator stores the challenge in a short-lived cache (5 min
TTL) so it can verify it was actually issued by this coordinator.

### Step 2: host signs with their CLN node

The host runs `signmessage` on their CLN node:

```
$ lightning-cli signmessage "soup-rendezvous:proof-of-node:v0:npub1zgq...wxurq:a1b2c3d4e5f6:1776374943"
{
   "signature": "c978...",
   "recid": "00",
   "zbase": "d9rzo78k9u9zds7bi8en..."
}
```

**Before signing, the host (or their wallet) MUST verify:**
- Message starts with `soup-rendezvous:proof-of-node:v0:`
- The coordinator npub matches the coordinator they intend to get
  vouched by (they should know this out-of-band)
- The timestamp is recent (not hours or days old)
- If ANY check fails: **do not sign** — someone may be trying to
  trick you into signing a message for a different purpose

### Step 3: host sends proof to coordinator

The host provides:
- Their Nostr pubkey (npub or hex)
- Their LN node ID (from `lightning-cli getinfo`)
- The zbase signature
- The challenge string
- Optionally: channel count and capacity

### Step 4: coordinator verifies

The coordinator runs:

```
$ soup-rendezvous vouch <host-npub> <node-id> <zbase> "<challenge>" \
    --channels 12 --capacity-sat 50000000 \
    --lightning-dir /var/lib/cln-signet
```

The vouch command:

1. **Validates the challenge format.** Must match
   `soup-rendezvous:proof-of-node:v0:<own-npub>:<hex>:<ts>`.
2. **Checks the coordinator npub is its own.** Prevents accepting
   proofs meant for a different coordinator.
3. **Checks the timestamp.** Rejects challenges older than 5 minutes.
4. **Calls `lightning-cli checkmessage`.** Verifies the zbase
   signature recovers to the claimed node_id.
5. **Publishes a vouch event (kind 38101)** to configured Nostr
   relays, binding the host's Nostr pubkey to their verified LN node.

### Step 5: wallets check the vouch

Wallets browsing factory advertisements fetch vouch events:

```json
["REQ", "vouches", {
  "kinds": [38101],
  "authors": ["<coordinator-pubkey>"],
  "#p": ["<advertisement-author-pubkey>"]
}]
```

The wallet checks:
- Vouch author is a trusted coordinator (from the wallet's
  configurable coordinator list)
- Vouch `p` tag matches the factory advertisement's author
- Optionally: verify the LN node exists in the gossip graph

Vouched hosts show as verified. Unvouched hosts are flagged.

## What CLN signmessage actually does

Under the hood, `lightning-cli signmessage` computes:

```
hash = sha256(sha256("Lightning Signed Message:" + message))
signature = ecdsa_sign_recoverable(hash, node_private_key)
output = zbase32_encode(signature)
```

`checkmessage` reverses this:

```
hash = sha256(sha256("Lightning Signed Message:" + message))
recovered_pubkey = ecdsa_recover(hash, signature)
verified = (recovered_pubkey == claimed_pubkey)
```

The "Lightning Signed Message:" prefix is CLN's own domain separator
at the cryptographic level. Our `soup-rendezvous:proof-of-node:v0:`
prefix is a second domain separator at the application level. Both
layers protect against different classes of replay.

## Other services that use CLN signmessage

Known uses and why there's no collision:

| Service | Expected message format | Collision risk |
|---------|----------------------|----------------|
| LNURL-auth | `lnurl:https://...` | None — different prefix |
| Amboss | Amboss-specific format | None — different prefix |
| Lightning address | service-specific | None — different prefix |
| soup-rendezvous | `soup-rendezvous:proof-of-node:v0:...` | Only valid for us |

If a future protocol also uses CLN signmessage, it should use its
own domain-separated prefix. If it doesn't, that's their
vulnerability, not ours.

## Security checklist

For the coordinator operator:
- [ ] Never accept a challenge you didn't issue (keep a cache)
- [ ] Reject challenges older than 5 minutes
- [ ] Verify the coordinator npub in the challenge is your own
- [ ] Verify checkmessage returns the claimed node_id
- [ ] Verify the node_id exists in the LN gossip graph (optional but recommended)

For the host being verified:
- [ ] Verify the challenge starts with `soup-rendezvous:proof-of-node:v0:`
- [ ] Verify the coordinator npub matches who you're trying to get vouched by
- [ ] Verify the timestamp is recent
- [ ] Never sign a message that doesn't match this format
- [ ] Never sign a message from an unknown coordinator
