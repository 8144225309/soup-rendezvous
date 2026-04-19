//! Event builders for the coordination protocol.
//!
//! Three Nostr event kinds, one DM shape. The protocol is deliberately
//! minimal — Nostr is the seed list of verified LSP contact pointers,
//! nothing else. Factory parameters, slots, joins, and seal flow all
//! happen LSP-to-wallet directly over Lightning after a wallet reads
//! the seed list and dials the LSP.

use nostr_sdk::prelude::*;

use crate::kinds;

/// Build the coordinator's root discovery thread event.
///
/// Kind 38099 with d-tag `"root"` — parameterized-replaceable, so
/// republishing (e.g. to update the description, refresh relay set,
/// or rotate keys) automatically replaces the prior version.
pub fn build_root_thread(description: &str) -> EventBuilder {
    EventBuilder::new(kinds::ROOT_THREAD, description).tag(Tag::identifier("root"))
}

/// Tier of a published vouch — encoded as the `["l", ...]` tag value
/// so wallets can filter at the relay layer via NIP-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VouchTier {
    /// proof-of-channel: chain-anchored via BOLT-7 gossip membership
    Channel,
    /// proof-of-utxo: chain-anchored via UTXO set
    Utxo,
    /// proof-of-peer: NOT chain-anchored
    Peer,
}

impl VouchTier {
    pub fn as_l_tag(&self) -> &'static str {
        match self {
            Self::Channel => "channel",
            Self::Utxo => "utxo",
            Self::Peer => "peer",
        }
    }

    pub fn from_l_tag(s: &str) -> Option<Self> {
        match s {
            "channel" => Some(Self::Channel),
            "utxo" => Some(Self::Utxo),
            "peer" => Some(Self::Peer),
            _ => None,
        }
    }
}

/// Build a vouch event — uniform shape across all three tiers.
///
/// Kind 38101, parameterized-replaceable with d-tag = host pubkey hex.
/// Republishing automatically replaces the prior version.
///
/// The published vouch is a **contact pointer** into the seed list:
/// the `ln_node_id` (LN pubkey wallets dial), an optional
/// `ln_addresses` list (host:port pairs, only needed if the node isn't
/// in BOLT-7 gossip), the tier label, and freshness metadata. All
/// other facts the coordinator verified (btc_address, channel count,
/// UTXO outpoint, feature bits) are deliberately stripped from
/// publication — everything else about the factory comes from dialing
/// the LSP directly over LN.
///
/// `btc_address_hash` is utxo-tier only: a truncated SHA-256 of the
/// verified bitcoin address, stored in a `["btc_hash", ...]` tag so
/// the daemon can rebuild per-address Sybil cap state on restart
/// without publishing the address itself. Wallets ignore this tag.
///
/// `expiry_unix` attaches a NIP-40 expiration tag. Hosts re-prove
/// before this passes; conformant relays drop the event after, and
/// conformant clients ignore it even if a non-conformant relay still
/// serves it.
pub fn build_vouch(
    host_pubkey: &PublicKey,
    tier: VouchTier,
    ln_node_id: &str,
    ln_addresses: &[String],
    btc_address_hash: Option<&str>,
    expiry_unix: u64,
) -> EventBuilder {
    let mut content = serde_json::json!({
        "status": "active",
        "ln_node_id": ln_node_id,
        "verified_at": Timestamp::now().as_secs(),
        "expires_at": expiry_unix,
    });
    if !ln_addresses.is_empty() {
        content["ln_addresses"] = serde_json::json!(ln_addresses);
    }

    let mut builder = EventBuilder::new(kinds::VOUCH, content.to_string())
        .tag(Tag::identifier(host_pubkey.to_hex()))
        .tag(Tag::public_key(*host_pubkey))
        .tag(Tag::custom(
            TagKind::custom("ln_node_id"),
            vec![ln_node_id.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
            vec![tier.as_l_tag().to_string()],
        ))
        .tag(Tag::expiration(Timestamp::from(expiry_unix)));

    if let Some(h) = btc_address_hash {
        builder = builder.tag(Tag::custom(
            TagKind::custom("btc_hash"),
            vec![h.to_string()],
        ));
    }

    builder
}

/// Build a vouch-revocation event.
///
/// Kind 38101 with the same d-tag (host pubkey hex) as the original
/// vouch — relays supersede the prior "active" event with this
/// "revoked" one. Clients MUST check `content.status` before trusting
/// any vouch. Carries the same NIP-40 expiration so it self-cleans.
pub fn build_revoke_vouch(
    host_pubkey: &PublicKey,
    tier: VouchTier,
    expiry_unix: u64,
) -> EventBuilder {
    let content = serde_json::json!({
        "status": "revoked",
        "revoked_at": Timestamp::now().as_secs(),
        "expires_at": expiry_unix,
    });

    EventBuilder::new(kinds::VOUCH, content.to_string())
        .tag(Tag::identifier(host_pubkey.to_hex()))
        .tag(Tag::public_key(*host_pubkey))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
            vec![tier.as_l_tag().to_string()],
        ))
        .tag(Tag::expiration(Timestamp::from(expiry_unix)))
}

// --- helpers for inspecting fetched vouch events ---

/// True if a fetched kind-38101 event is currently the active form of
/// a vouch: its NIP-40 expiration has not passed AND its content status
/// is `"active"`. A revoked or expired event counts as not active.
pub fn vouch_is_active(event: &Event) -> bool {
    let now = Timestamp::now().as_secs();
    for tag in event.tags.iter() {
        if tag.kind() == TagKind::Expiration
            && let Some(s) = tag.content()
            && let Ok(expires) = s.parse::<u64>()
            && expires <= now
        {
            return false;
        }
    }

    serde_json::from_str::<serde_json::Value>(&event.content)
        .ok()
        .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(String::from))
        .map(|s| s == "active")
        .unwrap_or(false)
}

/// Extract the `ln_node_id` tag from a vouch event, if present.
pub fn vouch_ln_node_id(event: &Event) -> Option<String> {
    get_tag_value(event, "ln_node_id")
}

/// Truncated SHA-256 of a bitcoin address, hex-encoded. Used in the
/// utxo-tier vouch's daemon-internal `["btc_hash", ...]` tag so the
/// daemon can rebuild per-address cap state at startup without
/// publishing the address itself. 24 hex chars = 96 bits — far more
/// than enough collision resistance for Sybil-cap purposes, and short
/// enough to keep vouches lean.
pub fn btc_address_hash(btc_address: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(btc_address.as_bytes());
    let full: [u8; 32] = h.finalize().into();
    hex::encode(&full[..12])
}

// --- helpers for extracting tags from fetched events ---

pub fn get_tag_value(event: &Event, tag_name: &str) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::custom(tag_name))
        .and_then(|t| t.content().map(|s| s.to_string()))
}

pub fn get_d_tag(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)))
        .and_then(|t| t.content().map(|s| s.to_string()))
}

pub fn get_e_tag(event: &Event) -> Option<EventId> {
    event.tags.iter().find_map(|t| {
        if t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)) {
            t.content().and_then(|s| EventId::from_hex(s).ok())
        } else {
            None
        }
    })
}
