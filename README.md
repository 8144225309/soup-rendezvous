# soup-rendezvous

Coordination protocol for multi-party Bitcoin signing, built on Nostr.

Users publish signed events to standard Nostr relays to find each other and form cohorts before running MuSig2, FROST, or covenant signing ceremonies. No custom server — any Nostr relay works out of the box.

Built for [Soup Wallet](https://github.com/8144225309/superscalar-wallet) and [SuperScalar](https://github.com/8144225309/superscalar) channel factories. Scheme-agnostic — the same event kinds work for any multi-party signing scheme without changes.

## How it works

Six Nostr event kinds handle the full lifecycle:

| Kind | Name | Visibility | Purpose |
|------|------|-----------|---------|
| 38099 | root thread | public | coordinator's identity post (replaceable, d-tag `"root"`) |
| 38100 | advertisement | public | host posts a factory opening with rules and capacity |
| 38101 | vouch | public | coordinator attests a host passed one of three verification methods |
| 38102 | status update | public | host posts slot-fill updates ("3/8 joined") |
| 38200 | attestation | encrypted | joiner requests to join (NIP-44 encrypted to host) |
| 38300 | seal | encrypted | host closes the cohort (NIP-44 encrypted to each member) |

Vouch events are unified across tiers and carry only the LN contact info wallets need to dial the host (`ln_node_id` + optional `ln_addresses`), the tier label (`["l", ...]` tag), freshness, and active/revoked status. Everything else (channel topology, bitcoin balances, UTXO outpoints, addresses) is verified by the coordinator and then deliberately stripped before publication so vouches don't leak host-side topology or financial info. Wallets discover factory state by dialing the host's LN node directly. See [Spam resistance](#spam-resistance) for the verification methods and [WALLET_INTEGRATION.md §2](./WALLET_INTEGRATION.md) for the full vouch field reference.

A **coordinator** publishes a root discovery thread and vouches for factory hosts after verifying their identity via one of three methods. Wallets browse advertisements, check vouches, and join by publishing encrypted attestations. When the host seals the cohort, each member receives an encrypted manifest with the full member list and connection info. The seal is the handoff — after it, the wallet peers with the LSP over Lightning and all signing, state updates, and factory operations flow over the direct LN connection (custommsg 33001). Nostr is not involved after the seal.

## Freshness: use it or lose it

Every vouch and every ad carries a NIP-40 `expiration` tag. If the publisher doesn't refresh before it passes, conformant relays drop the event and conformant clients ignore it. This makes the dataset **self-pruning** — there is no coordinator-side liveness polling and no operator-run cleanup job.

Defaults (all adjustable):

| Event | Default lifetime | Refresh by | Knob |
|-------|-----------------|------------|------|
| Vouch (38101) | 30 days | host re-running `request-vouch` every 2–3 weeks | `--vouch-expiry-days` on `vouch`, `SOUP_VOUCH_EXPIRY_DAYS` env on daemon |
| Advertisement (38100) | 48 hours | host re-publishing the ad every 1–2 days | `--expiry-hours` on `test-ad` / equivalent arg when hosts build their own |

### Per-identifier vouch caps

The coordinator bounds how many simultaneously-active vouches it will issue per verified identifier, rising tighter as the Sybil anchor weakens:

| Method | Identifier | Default cap | Knob |
|---|---|---|---|
| channel | LN node pubkey | 10 | `max_active_vouches_per_ln_node` (also `SOUP_MAX_ACTIVE_VOUCHES_PER_LN_NODE`) |
| utxo | truncated SHA-256 of bitcoin address | 10 | same knob as channel |
| peer | LN peer pubkey | 3 | `max_active_vouches_per_peer` (also `SOUP_MAX_ACTIVE_VOUCHES_PER_PEER`) |

For utxo-tier the cap is keyed on a 12-byte SHA-256 hash of the verified bitcoin address, written to a daemon-internal `["btc_hash", ...]` tag on the published vouch. Lets the coordinator rebuild per-address cap state on restart without ever publishing the address itself. Wallets ignore that tag.

Caps block a single underlying identity from flooding the attestation list by rotating Nostr keys — a cheap amplification attack at the Nostr layer where each fresh key yields another vouch event that every wallet has to ingest and filter.

Before publishing, the daemon consults its **in-memory vouch table** — an authoritative view populated from relays at startup and maintained on every publish. Cap check costs microseconds, not a relay round-trip. The table re-syncs from relays every hour to catch drift, and the daemon logs a warning if it discovers any.

**Same-identity refreshes are handled by the per-sender rate limit, not the cap.** When a host refreshes their own vouch using the same Nostr key, the d-tag matches the existing entry, so replaceable-event semantics *supersede* the old vouch rather than pile on top. That means the cap would falsely include the about-to-be-replaced vouch in the count, so the cap check explicitly excludes the requesting identity's own d-tag. What limits single-identity refresh spam is the per-sender rate limit (5/hour, 1/minute on the requesting Nostr pubkey). Different mechanism for different shape of misuse.

### Split rate-limit buckets

The global request ceiling is split by proof type so peer-tier traffic can't starve chain-anchored traffic:

| Bucket | Methods counted | Default |
|---|---|---|
| Chain-anchored | channel + utxo | 80 requests / hour |
| Peer | peer | 20 requests / hour |

The per-sender rate limit (5/hour, 1/minute per Nostr pubkey) applies uniformly to every method.

Wallets SHOULD additionally dedup listings by the method-appropriate identifier — see `WALLET_INTEGRATION.md` §2 check 5a.

The numbers reflect operational reality: LSPs running factories should be able to keep listings alive with a daily-ish cron job (48h leaves a buffer for one missed refresh); proof-of-channel/utxo is slightly heavier (one signmessage round-trip plus a DM) so a monthly cadence is friendlier, with three weeks of refresh window.

Hosts can automate refresh with a systemd timer, e.g.:

```ini
# /etc/systemd/system/soup-vouch-refresh.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/soup-rendezvous request-vouch <coordinator-npub> \
  --lightning-dir=/var/lib/cln-signet

# /etc/systemd/system/soup-vouch-refresh.timer
[Timer]
OnCalendar=*-*-01,15 03:00       # twice a month
Persistent=true

[Install]
WantedBy=timers.target
```

## List model: no history replay

Kinds 38099, 38100, and 38101 are **parameterized-replaceable** (NIP-33). Each is addressed by `(kind, author, d-tag)`; republishing with the same triple causes every conformant relay to drop the prior version. Clients filter once — e.g. `kind:38101, author:<coordinator>` — and receive only the current state, never the history.

Consequences:
- Updates cost nothing. A host can refresh their advertisement as often as needed; a coordinator can re-emit a vouch to update channel counts or revoke it.
- **Revocation is trivial.** `soup-rendezvous revoke-vouch <host-npub>` republishes the kind-38101 event for that host with `{"status":"revoked", "reason":"..."}`. Relays supersede the prior "active" vouch. Wallets MUST verify `content.status == "active"` before accepting a vouch.
- No month-long history scan required. Factory ads additionally carry NIP-40 expiration tags; clients use a `since` filter to drop stale entries automatically.

## Spam resistance

Three verification paths, two chain-anchored and one acknowledged-weak:

- **Proof-of-channel** ([details](./PROOF_OF_CHANNEL.md), chain-anchored) — factory hosts prove control of a Lightning node with ≥1 announced channel by signing a challenge with CLN's `signmessage`. The coordinator verifies with `checkmessage`, which enforces gossip-graph membership (chain-anchored via channel funding).
- **Proof-of-UTXO** ([details](./PROOF_OF_UTXO.md), chain-anchored) — hosts who don't have an LN node can prove control of an on-chain bitcoin address holding at least one unspent output. The coordinator verifies with `bitcoin-cli verifymessage` + `gettxout` (chain-anchored via the UTXO set).
- **Proof-of-peer** ([details](./PROOF_OF_PEER.md), *off by default on mainnet*) — hosts with neither channels nor funded UTXOs can prove key possession + daemon reachability via a BOLT-8 Noise handshake the coordinator initiates. No chain anchor. Tighter caps and separate rate bucket. Wallets SHOULD default to hiding peer-tier vouches.

Wallets filter unvouched advertisements by default. For chain-anchored tiers, spammers need either a funded LN channel or a funded UTXO per Sybil identity — both cost real on-chain bitcoin.

**Tier selection guidance.** Hosts SHOULD pick the strongest verification method they can satisfy: proof-of-channel first if they have any announced channel, proof-of-UTXO if they have on-chain bitcoin but no channels, proof-of-peer otherwise. Wallets SHOULD prefer chain-anchored tiers in display ordering since peer-tier is the lowest tier and more susceptible to flooding; results may be filtered down or hidden behind an opt-in.

**Young-peer safety: use multi-method DMs.** A freshly-funded LN channel won't be in the coordinator's BOLT-7 gossip view for minutes to hours after the funding transaction confirms. Any host that can produce more than one proof method SHOULD always send a `proof_multi` DM (see [WALLET_INTEGRATION.md §7.1a](./WALLET_INTEGRATION.md)) rather than single-method. The coordinator tries each proof in order and publishes at the first tier that verifies — so a new operator who just opened their first channel still gets vouched immediately via the UTXO fallback while gossip catches up. No back-and-forth required, no legitimate operator filtered out for being correct-and-fast.

**How verification cascades and how wallets filter.** The coordinator only verifies what the host submits. With `proof_multi`, it tries each submitted proof in order and publishes **one vouch at the first tier that verifies**. A host therefore holds at most one active vouch per coordinator (d-tag = host pubkey hex), labeled with the tier that won. Every vouch — channel, utxo, or peer — carries the same minimal payload: the host's LN node id (so wallets know which node to dial), an optional address list (for hosts not in BOLT-7 gossip), the tier `l` tag, and freshness. Because the tier label is a NIP-01 single-letter `l` tag, wallets filter tier-first at the relay layer: query `"#l":["channel"]` first, then `"#l":["utxo"]`, and `"#l":["peer"]` only behind an explicit opt-in. A flood at peer-tier cannot pollute a channel-tier query. See [WALLET_INTEGRATION.md §2](./WALLET_INTEGRATION.md) for the recommended discovery sequence and the per-tier field reference.

## CLI tool

The repo includes a Rust CLI for the coordinator and for testing the full flow:

```
soup-rendezvous init              generate a Nostr keypair
soup-rendezvous publish-root      post the root discovery thread
soup-rendezvous test-ad <root>    post a factory advertisement
soup-rendezvous update-status     post slot-fill status updates
soup-rendezvous list-ads          browse factories from relays
soup-rendezvous challenge         generate a proof-of-channel challenge
soup-rendezvous vouch             verify an LN node proof and publish a vouch
soup-rendezvous revoke-vouch      revoke a previously-published vouch
soup-rendezvous list-vouches      list verified node proofs
soup-rendezvous request-vouch       (host) send a proof-of-channel DM to a coordinator
soup-rendezvous request-vouch-utxo  (host) send a proof-of-UTXO DM to a coordinator
soup-rendezvous request-vouch-peer  (host) send a proof-of-peer DM to a coordinator
soup-rendezvous request-vouch-multi (host) send one DM with multiple proofs; coordinator publishes at the best tier that verifies
soup-rendezvous join <ad>         publish an encrypted join request
soup-rendezvous review-joins      decrypt and review join requests (host)
soup-rendezvous accept            accept a joiner with encrypted confirmation DM (host)
soup-rendezvous seal <ad>         seal the cohort with accepted members (host)
soup-rendezvous show-cohort <ad>  view the full cohort state
```

## Integration

See [WALLET_INTEGRATION.md](./WALLET_INTEGRATION.md) for the full protocol contract: event schemas, Nostr subscription filters, NIP-44 encryption, the three verification methods (channel / utxo / peer), seal manifest structure, rules-hash enforcement at signing time, and post-factory communication patterns.

## Multi-network deployment

One binary can serve multiple networks (mainnet / signet / testnet4) by pointing `--config` at a TOML file and `--network` at a section name. Each network has its own Nostr identity, its own CLN RPC socket, and its own state directory.

`deploy/soup-rendezvous.example.toml`:
```toml
relays = ["wss://nos.lol", "wss://relay.damus.io", "..."]
vouch_expiry_days = 30

[networks.signet]
key_file = "/var/lib/soup-rendezvous-signet/coordinator.nsec"
lightning_dir = "/var/lib/cln-signet"            # proof-of-channel
bitcoin_dir = "/var/lib/bitcoind-signet"         # proof-of-UTXO
min_utxo_balance_sat = 0                         # permissive on test networks
allow_peer_verification = true                   # proof-of-peer on (test only)

[networks.mainnet]
key_file = "/var/lib/soup-rendezvous-mainnet/coordinator.nsec"
lightning_dir = "/var/lib/cln-mainnet"
bitcoin_dir = "/var/lib/bitcoind"
min_utxo_balance_sat = 100000                    # ~$60 Sybil floor
# allow_peer_verification deliberately unset (false by default) on mainnet
vouch_expiry_days = 14
```

Drop it at `/etc/soup-rendezvous.toml`, then use the systemd template unit (`deploy/soup-rendezvous@.service`) to run instances per network:

```bash
systemctl enable --now soup-rendezvous@signet.service
systemctl enable --now soup-rendezvous@mainnet.service
```

Each `%i` in the template expands to the instance name (`signet`, `mainnet`, …) which drives both `--network=%i` and the state paths (`/var/lib/soup-rendezvous-%i`, `/var/lib/cln-%i`). Precedence: per-network value in config beats top-level default; explicit `--config` picks the section as the single source of truth per run.

### Managing the config file

**Editing.** `/etc/soup-rendezvous.toml` is read once at daemon startup. After a change, restart the affected instance:

```bash
systemctl restart soup-rendezvous@signet.service
```

Only the instance you restart picks up the edit — the others keep running against their own loaded config. Use `systemctl restart 'soup-rendezvous@*.service'` to cycle all of them.

**Ad-hoc / one-off commands.** The same `--config` / `--network` flags work on every subcommand, not just `daemon`. To publish a root thread, revoke a vouch, or list events against a specific network:

```bash
soup-rendezvous --config /etc/soup-rendezvous.toml --network signet whoami
soup-rendezvous --config /etc/soup-rendezvous.toml --network testnet4 publish-root "..."
soup-rendezvous --config /etc/soup-rendezvous.toml --network signet revoke-vouch <host-npub> --reason "..."
```

**Adding a new network later.** Generate the nsec, uncomment the corresponding section in the config, enable the template instance, and publish its root thread. The systemd template handles path expansion automatically — you do not touch the unit file.

```bash
install -d -m 700 /var/lib/soup-rendezvous-mainnet
soup-rendezvous --key-file /var/lib/soup-rendezvous-mainnet/coordinator.nsec init
# edit /etc/soup-rendezvous.toml, uncomment [networks.mainnet]
systemctl enable --now soup-rendezvous@mainnet.service
soup-rendezvous --config /etc/soup-rendezvous.toml --network mainnet publish-root "..."
```

**Settings that are NOT in the config (by design).** Rate limits, replay cache TTL, challenge timestamp skew, and metrics interval are currently compiled-in constants. They do not vary between networks and the defaults have been tuned for general use. Operators who need to override them can patch and rebuild. If real operational need emerges, we can promote them into the config later.

**Nothing secret goes in the TOML.** The config file holds paths and URLs only; the actual nsecs sit in their own files referenced by `key_file`, with `chmod 600 root:root`. Don't put secrets in the TOML.

### Tor / SOCKS5 proxy (optional)

All Nostr websocket traffic can be routed through a SOCKS5 proxy — intended primarily for point-to-Tor deployments where the coordinator operator wants to hide the coordinator's IP from relay operators. Note the honest caveat: **the coordinator's npub is the identity, and npubs are smoking guns by design** — wallets find the coordinator by looking up the npub, so the pubkey is always public. Tor hides your *infrastructure* (the TCP endpoint), not your *identity* (the key).

**Enabling it.** Install a tor daemon on the host, let it bind SOCKS5 to `127.0.0.1:9050` (the Debian/Ubuntu default), then add one line to the config:

```toml
# /etc/soup-rendezvous.toml
proxy_url = "127.0.0.1:9050"
```

Top-level applies to every network; a per-network override works the same way:

```toml
[networks.mainnet]
key_file = "..."
lightning_dir = "..."
proxy_url = "127.0.0.1:9050"    # only this network's traffic goes through tor
```

Or set it ad-hoc via env / CLI:

```bash
SOUP_PROXY_URL=127.0.0.1:9050 soup-rendezvous --config /etc/soup-rendezvous.toml --network signet daemon
# or
soup-rendezvous --proxy-url 127.0.0.1:9050 ...
```

**What it actually does.** Every outbound websocket to a Nostr relay is negotiated through the SOCKS5 proxy. Inbound DMs arrive through the same proxied subscriptions. Zero code changes inside your integrating LSP or wallet — the proxy is entirely a coordinator-side concern.

**Tradeoffs.**
- Adds 100–500 ms of latency per relay hop. Vouching round-trips get slower.
- Tor circuit changes can cause brief relay disconnects; nostr-sdk reconnects automatically but metrics will show short-lived drops.
- Not a mixnet — relays still see "a tor exit node" connecting with your npub. Correlating activity to a single operator is still possible across enough observations.
- Any relay that blocks tor exits will stop working for you.

**When to enable it.** If your deployment has a specific adversary model where hiding the VPS IP matters. For most operators, running on a bare VPS without tor is fine; the npub was always going to be public, and a fixed VPS IP is no worse than any other public service.

**When NOT to enable it.** If you're running on a hosted setup where tor isn't installed, don't add it just because. Every added dependency is a new operational surface. Ship without it; add it if a threat model emerges.

## Running your own coordinator

`soup-rendezvous init` generates a Nostr keypair and writes the `nsec` (private key) to disk. The `nsec` **is** the coordinator's identity — everything you publish is signed by it, and losing it means losing the identity forever. There is no cryptographic recovery.

Recommended v0 setup (what this repo's reference deployment does):

1. Run `soup-rendezvous init` on the VPS.
2. Move the nsec to `/var/lib/soup-rendezvous/coordinator.nsec` (`chmod 600`, `chown root:root`; parent dir `700`).
3. Copy it once to `/root/soup-rendezvous-keybackup/coordinator.nsec` as a local backup, and drop a `coordinator-info.md` alongside it with the npub, root-thread event id, relay list, and recovery procedure.
4. Record the npub somewhere under your control — if the VPS dies, that's how you prove which identity was yours.

For production use, add: an encrypted off-VPS backup (`age` or GPG) in your password manager and on an offline drive, and eventually a hardware signer. Rotation means generating a new key, publishing a migration event signed by the old key, and re-announcing the new npub. Nobody relying on the old npub can be auto-migrated — plan accordingly.

### Bring your own key

This CLI deliberately does **not** build custodial key storage, backup automation, or rotation tooling. A coordinator `nsec` is cryptographically equivalent to a Bitcoin signing key and the same rules apply:

- **Your key, your responsibility.** `soup-rendezvous init` generates a fresh Nostr keypair and writes the `nsec` (bech32) to the configured file, but you can equally hand-write any valid secret key there — the daemon only requires that the file contain an `nsec1…` or 64-char hex secret.
- **Use any Nostr-native key-management workflow** you already run: `nsecbunker`, a hardware signer via NIP-07 or remote signing via NIP-46, an `age`- or GPG-encrypted blob in your password manager, or a paper backup in a safe. All are compatible as long as the final `nsec` can be written to the key file the daemon reads at startup.
- **No recovery path.** If the `nsec` is lost, the coordinator identity is lost — there is no seed phrase, no Shamir split, no social recovery. Generate a new key, publish a fresh root thread, and announce the new `npub` out-of-band (email, blog post, a pinned note signed by the old key) so existing clients can migrate.
- **Rotate on compromise, not on a clock.** Every rotation forces every client that has the old `npub` in its accepted-coordinator list to update. The benefit of scheduled rotation is small when the key is kept offline or in a hardware signer; the ops cost is not.

For a real deployment: keep at least one encrypted copy off the host, treat the `nsec` as write-once until you have to rotate, and never move it through any channel that could log it.

## Reference coordinators

The coordinator daemons operated from this repo publish the following Nostr identities. Wallets integrating with this protocol can preload these in their accepted-coordinator list (user-editable).

| Network | Status | npub |
|---|---|---|
| signet | live | `npub1zgqcy07tv2gqupug3mrufce9nsjccvta6ynawle54wk2ma7vw96s3wxurq` |
| testnet4 | live | `npub1dh4rzrpttf94pajglfqrvad2lcaqxncurj4p3keaj43vqrsdvw3q8aq8qr` |
| mainnet | live | `npub103gc9tm8apf56w56mtcw5r5crz84d6hldk06vkmw8ulaht6ddu8qd7vw4j` |

Mainnet configuration: proof-of-channel and proof-of-UTXO are active (cln-mainnet peered with public gossip-capable nodes, bitcoind mainnet synced). Peer-tier is off by default on mainnet. Mainnet vouch expiry is 14 days (shorter than the 30-day default on signet/testnet4) to reduce stale-vouch exposure.

All three publish to the same relay set listed below.

## Status

Early prototype. The CLI and daemon are live on 7 free public Nostr relays (nos.lol, relay.damus.io, relay.primal.net, relay.nostr.band, relay.snort.social, offchain.pub, nostr.fmt.wiz.biz). All three verification methods have been exercised end-to-end on signet:

- Proof-of-channel — signed with a real signet CLN node, verified via `checkmessage` against the coordinator's own gossip graph.
- Proof-of-UTXO — signed with a real signet bitcoin address, verified via `bitcoin-cli verifymessage` + `gettxout`.
- Proof-of-peer — verified via a BOLT-8 Noise handshake to a signet LN node with the coordinator's CLN.

## License

MIT
