# Proof-of-UTXO Verification

How factory hosts prove they control a Bitcoin address holding at least one unspent output to get vouched by the soup-rendezvous coordinator — without needing a Lightning node or any announced channels.

**Sibling documents:** [PROOF_OF_CHANNEL.md](./PROOF_OF_CHANNEL.md) for the Lightning-anchored variant, [PROOF_OF_PEER.md](./PROOF_OF_PEER.md) for the weak-tier variant used when neither channels nor UTXOs are available.

## Tier selection

Pick the strongest verification method you can satisfy. The ordering from strongest to weakest:

1. **proof-of-channel** — use if you have any announced LN channel. Chain-anchored via the channel's funding UTXO.
2. **proof-of-utxo** (this document) — use if you don't have LN channels yet but have on-chain bitcoin in a wallet with signmessage support. Chain-anchored via your UTXO.
3. **proof-of-peer** — use as a last resort. Lowest tier, no chain anchor, susceptible to flooding, so wallets may filter peer-tier vouches down or behind an opt-in.

Channel and UTXO are both chain-anchored and co-equal in trust. Use proof-of-utxo when you hold bitcoin but don't run Lightning infrastructure (yet). If you later open channels, you can upgrade to proof-of-channel at any refresh cycle.

### Graceful fallback for young peers

Proof-of-UTXO has a second use case beyond "operator without any LN node": it's the natural **fallback for a host whose LN channel is real but too young for the coordinator's gossip view**. BOLT-7 gossip propagation is eventually-consistent and takes minutes-to-hours; a channel opened 5 minutes ago will produce a valid `signmessage` but will fail `checkmessage` because the coordinator hasn't heard the `channel_announcement` yet.

A host in this situation should include a proof-of-UTXO proof **alongside** their proof-of-channel in a multi-method DM (see [WALLET_INTEGRATION.md §7.1a and §7.1b](./WALLET_INTEGRATION.md)). The coordinator:
1. Tries channel first → fails due to gossip gap.
2. Falls through to utxo → succeeds immediately.
3. Publishes a utxo-tier vouch — the host is live.

When gossip catches up, the host re-runs the multi-method request and channel-tier succeeds, superseding the earlier utxo-tier vouch under the same d-tag.

This prevents the "fast operator does everything right but gets filtered" failure mode.

## Why this exists

Not every host that wants to run a factory already has Lightning channels. An individual with bitcoin in their wallet should be able to bootstrap into a factory ceremony using their on-chain funds as proof of identity. Proof-of-UTXO gives them that path while keeping the coordinator's Sybil resistance chain-anchored: each fresh "identity" still costs real bitcoin in real UTXOs.

## Why this is chain-anchored, despite not touching Lightning

The coordinator verifies proof-of-UTXO by running:

1. `bitcoin-cli verifymessage <btc_address> <signature> <challenge>` — standard ECDSA signature recovery against the address's pubkey.
2. `bitcoin-cli gettxout <txid> <vout>` — reads the live UTXO set. Returns the UTXO's script, value, and confirmations, or nothing if the output has been spent.

Step 2 is what anchors the proof to the chain. A UTXO is fundamentally scarce — it requires a confirmed Bitcoin transaction to create, real BTC to fund, and becomes unspendable when spent. You can't fabricate one. Getting a second UTXO requires either sending from the first (paying a fee and forfeiting the original) or bringing more bitcoin from elsewhere. Either way, the Sybil cost is denominated in real bitcoin + real fees.

This is the same chain-anchor class as proof-of-channel, just one layer below: channel announcements prove "at least one funded channel exists," while UTXO verification proves "at least one unspent output exists." Both come from the same Bitcoin UTXO set.

## One-shot, host-driven

Same shape as proof-of-channel. The host does all the work; the coordinator validates:

```
1. Host constructs a challenge using publicly known inputs.
2. Host signs the challenge with its bitcoin wallet (signmessage).
3. Host sends challenge + signature + UTXO outpoint in one
   encrypted kind-4 DM.
4. Coordinator validates, calls verifymessage + gettxout, and
   publishes the vouch event (kind 38101, l=utxo).
5. Coordinator sends a confirmation DM back.
```

## Challenge format

```
soup-rendezvous:proof-of-utxo:v0:<coordinator-npub>:<random-hex>:<unix-timestamp>
```

Example:
```
soup-rendezvous:proof-of-utxo:v0:npub1zgqcy07tv2gqu...s3wxurq:7a2c4d12de8f0b4a:1776374943
```

Field purposes are identical to proof-of-channel — see [PROOF_OF_CHANNEL.md](./PROOF_OF_CHANNEL.md#field-purposes). The only difference is the action tag (`proof-of-utxo` vs `proof-of-channel`).

### Why the action-tag separator matters

A signature produced against `proof-of-utxo:v0:...` cannot be replayed as a proof-of-channel attestation (wrong prefix) or against any other LN/Bitcoin service that uses its own signmessage prefix. Domain separation is a cheap defense and we inherit it automatically from the challenge format.

## Request payload

The encrypted DM carries:

```json
{
  "type":        "proof_of_utxo",
  "btc_address": "bc1q...",
  "signature":   "HzCvA...",          // bitcoin-cli signmessage output
  "challenge":   "soup-rendezvous:proof-of-utxo:v0:<coord-npub>:<hex>:<ts>",
  "utxo_txid":   "<64-hex>",
  "utxo_vout":   0
}
```

`utxo_txid` and `utxo_vout` specify exactly which unspent output the host is using as proof. The coordinator uses these to query bitcoind directly — no wallet import or `scantxoutset` is required; `gettxout` reads the UTXO set in milliseconds.

## Coordinator checks

In order (cheap checks first):

1. Request has `type: "proof_of_utxo"`.
2. Challenge has the right prefix, coordinator npub, and the timestamp is within ±5 minutes.
3. Replay cache: `(sender, challenge)` not seen in the last 10 minutes.
4. **Per-btc-address cap** (default 10 active vouches): cheap in-memory lookup. If at cap, reject before doing any subprocess work.
5. `bitcoin-cli verifymessage` returns `true` for the provided `(btc_address, signature, challenge)` tuple.
6. `bitcoin-cli gettxout` returns a UTXO record confirming:
   - the output exists and is unspent,
   - its scriptPubKey resolves to `btc_address`,
   - its value meets the configured `min_utxo_balance_sat`.
7. Publish a vouch event and record it in the in-memory table.

If any of 1–6 fails, the coordinator bails with a structured reason (logged via the audit line) and does not publish a vouch.

## Operator configuration

```toml
[networks.signet]
bitcoin_dir = "/var/lib/bitcoind-signet"
min_utxo_balance_sat = 0                  # permissive — any UTXO counts

[networks.mainnet]
bitcoin_dir = "/var/lib/bitcoind"
min_utxo_balance_sat = 100000             # ~$60 per Sybil (recommended)
```

`min_utxo_balance_sat = 0` is the permissive default: any unspent output, even dust, satisfies the threshold. For mainnet deployments you probably want a non-zero floor; `100000` (0.001 BTC) is a reasonable baseline.

Wallets observe the coordinator's accepted balance in the vouch's `verified_balance_sat` content field and can apply their own additional filter if they want stronger guarantees than the coordinator's floor provides.

## Security checklist

For the coordinator operator:
- [ ] Reject challenges that don't start with `soup-rendezvous:proof-of-utxo:v0:`
- [ ] Reject challenges whose coordinator npub isn't your own
- [ ] Reject challenges where `|now − ts| > 300` seconds
- [ ] Maintain a short-TTL replay cache keyed by `sha256(sender_pubkey || challenge)`
- [ ] Verify `verifymessage` returns `true` against the claimed `btc_address`
- [ ] Verify `gettxout` confirms the UTXO exists, is unspent, matches the address, and holds ≥ `min_utxo_balance_sat`
- [ ] Enforce the per-bitcoin-address active-vouch cap before running any subprocess

For the host being verified:
- [ ] Your bitcoin wallet must have the private key for the address you're signing with (most desktop wallets and CLI tools expose `signmessage`)
- [ ] The UTXO you reference must be unspent and confirmed
- [ ] The challenge you generate starts with `soup-rendezvous:proof-of-utxo:v0:` and contains the coordinator's npub you intend to submit to
- [ ] The timestamp you embed is the current time (within a minute or two)
- [ ] Never sign a message that doesn't match this exact format — especially not one that was handed to you by a third party
- [ ] Never submit to a coordinator whose npub you don't recognize

## Edge cases worth knowing

- **UTXO spent between sign time and check time.** The coordinator checks the UTXO's current state at verification time. If you signed but then spent the output before the DM arrived, `gettxout` returns empty and the proof fails. Fund a fresh UTXO and retry.
- **Fee-bump / RBF replacement changes the txid.** If you RBF a transaction before it confirms, the resulting UTXO has a different `(txid, vout)`. Always reference the confirmed transaction's values.
- **Shuffling the same BTC through many addresses.** Each "new" address needs its own funded UTXO, which costs a tx fee per move. Combined with the per-address vouch cap, amplification attempts pay roughly a fee per vouch.
- **Address format compatibility.** The coordinator supports any address format `bitcoin-cli verifymessage` supports. Older bitcoind versions may not support BIP-322 signatures for bech32/taproot addresses; check your version. P2PKH legacy addresses always work.
