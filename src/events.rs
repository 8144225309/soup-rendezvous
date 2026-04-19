//! Event builders for the coordination protocol.

use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::kinds;

/// SuperScalar factory parameters carried in the advertisement content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperScalarPayload {
    pub lsp_pubkey: String,
    pub lsp_endpoints: Vec<String>,
    pub lsp_nostr_relays: Vec<String>,
    pub total_funding_sat: String,
    pub client_contribution_sat: String,
    pub lsp_liquidity_sat: String,
    pub leaf_arity: u32,
    pub epoch_count: u32,
    pub lifetime_blocks: u32,
    pub dying_period_blocks: u32,
    pub lsp_fee_sat: String,
    pub lsp_fee_ppm: u32,
}

/// Joiner's attestation payload (encrypted to host via NIP-44).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPayload {
    pub joiner_cln_pubkey: String,
    pub joiner_cln_endpoint: String,
    pub joiner_nostr_relays: Vec<String>,
    pub nonce: String,
    pub message: String,
}

/// Seal manifest (encrypted to each cohort member via NIP-44).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealManifest {
    pub advertisement_id: String,
    pub rules_hash: String,
    pub members: Vec<SealMember>,
    pub sealed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealMember {
    pub nostr_pubkey: String,
    pub cln_pubkey: String,
    pub cln_endpoint: String,
    pub slot: u32,
}

/// Build the coordinator's root discovery thread event.
///
/// Kind 38099 with d-tag `"root"` — parameterized-replaceable, so
/// republishing (e.g. to update the description, refresh relay set,
/// or rotate keys) automatically replaces the prior version.
pub fn build_root_thread(description: &str) -> EventBuilder {
    EventBuilder::new(kinds::ROOT_THREAD, description).tag(Tag::identifier("root"))
}

/// Build a factory advertisement event.
#[allow(clippy::too_many_arguments)]
pub fn build_advertisement(
    root_event_id: &EventId,
    cohort_name: &str,
    scheme: &str,
    min_members: u32,
    max_members: u32,
    tags: &[&str],
    expiry_unix: u64,
    content: &str,
) -> EventBuilder {
    let mut builder = EventBuilder::new(kinds::ADVERTISEMENT, content)
        .tag(Tag::identifier(cohort_name))
        .tag(Tag::event(*root_event_id))
        .tag(Tag::custom(
            TagKind::custom("scheme"),
            vec![scheme.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("min_members"),
            vec![min_members.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("max_members"),
            vec![max_members.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("slots"),
            vec![format!("0/{max_members}")],
        ))
        .tag(Tag::custom(
            TagKind::custom("expiry"),
            vec![expiry_unix.to_string()],
        ))
        .tag(Tag::expiration(Timestamp::from(expiry_unix)));

    for t in tags {
        builder = builder.tag(Tag::hashtag(*t));
    }

    builder
}

/// Build a status update event for a factory.
pub fn build_status_update(
    ad_event_id: &EventId,
    scheme: &str,
    status: &str,
    accepted_count: u32,
    max_members: u32,
    message: &str,
) -> EventBuilder {
    let content = serde_json::json!({
        "message": message,
        "accepted_count": accepted_count,
        "max_members": max_members,
    });

    EventBuilder::new(kinds::STATUS_UPDATE, content.to_string())
        .tag(Tag::event(*ad_event_id))
        .tag(Tag::custom(
            TagKind::custom("scheme"),
            vec![scheme.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("status"),
            vec![status.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("slots"),
            vec![format!("{accepted_count}/{max_members}")],
        ))
}

/// Build a vouch event.
///
/// Kind 38101, parameterized-replaceable with d-tag = host pubkey hex.
/// Republishing (e.g. to refresh channel counts, to renew ahead of
/// expiry, or to revoke via [`build_revoke_vouch`]) automatically
/// replaces the prior version.
///
/// `expiry_unix` attaches a NIP-40 expiration tag. Hosts are expected
/// to re-prove before this passes; conformant relays will drop the
/// event after, and conformant clients will ignore it even if a
/// non-conformant relay still serves it.
pub fn build_vouch(
    host_pubkey: &PublicKey,
    ln_node_id: &str,
    channel_count: u32,
    capacity_sat: &str,
    expiry_unix: u64,
) -> EventBuilder {
    let content = serde_json::json!({
        "status": "active",
        "verification_source": "ln_channel",
        "ln_node_id": ln_node_id,
        "channel_count": channel_count,
        "capacity_sat": capacity_sat,
        "verified_at": Timestamp::now().as_secs(),
        "expires_at": expiry_unix,
    });

    EventBuilder::new(kinds::VOUCH, content.to_string())
        .tag(Tag::identifier(host_pubkey.to_hex()))
        .tag(Tag::public_key(*host_pubkey))
        .tag(Tag::custom(
            TagKind::custom("ln_node_id"),
            vec![ln_node_id.to_string()],
        ))
        // Single-letter filterable tag so wallets can query by proof
        // type via NIP-01 filters (#l). Patch B will add "utxo" and
        // "peer" values for the two additional verification methods.
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
            vec!["channel".to_string()],
        ))
        .tag(Tag::expiration(Timestamp::from(expiry_unix)))
}

/// Build a proof-of-UTXO vouch event.
///
/// Kind 38101, parameterized-replaceable with d-tag = host pubkey
/// hex (identical to proof-of-channel vouches; wallets can still
/// dedup by `(source, identifier)`). Tagged with `["l", "utxo"]` for
/// relay-layer filtering; content carries `verification_source =
/// "btc_utxo"`, the claimed bitcoin address, and the actual UTXO
/// balance the coordinator observed at verification time.
pub fn build_vouch_utxo(
    host_pubkey: &PublicKey,
    btc_address: &str,
    verified_balance_sat: u64,
    utxo_txid: &str,
    utxo_vout: u32,
    expiry_unix: u64,
) -> EventBuilder {
    let content = serde_json::json!({
        "status": "active",
        "verification_source": "btc_utxo",
        "btc_address": btc_address,
        "verified_balance_sat": verified_balance_sat.to_string(),
        "utxo_txid": utxo_txid,
        "utxo_vout": utxo_vout,
        "verified_at": Timestamp::now().as_secs(),
        "expires_at": expiry_unix,
    });

    EventBuilder::new(kinds::VOUCH, content.to_string())
        .tag(Tag::identifier(host_pubkey.to_hex()))
        .tag(Tag::public_key(*host_pubkey))
        .tag(Tag::custom(
            TagKind::custom("btc_address"),
            vec![btc_address.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
            vec!["utxo".to_string()],
        ))
        .tag(Tag::expiration(Timestamp::from(expiry_unix)))
}

/// Build a proof-of-peer vouch event.
///
/// Kind 38101, d-tag = host pubkey hex. Tagged `["l", "peer"]` for
/// relay-layer filtering. Content carries `verification_source =
/// "ln_peer"`, the peer's LN pubkey, their advertised addresses, and
/// optionally the feature bits observed during the BOLT-8 init
/// exchange.
///
/// Peer verification has **no chain anchor**. Wallets accepting
/// peer-tier vouches should make that an opt-in user choice, not a
/// default.
pub fn build_vouch_peer(
    host_pubkey: &PublicKey,
    peer_pubkey: &str,
    peer_addresses: &[String],
    features_hex: Option<&str>,
    expiry_unix: u64,
) -> EventBuilder {
    let mut content = serde_json::json!({
        "status": "active",
        "verification_source": "ln_peer",
        "peer_pubkey": peer_pubkey,
        "peer_addresses": peer_addresses,
        "verified_at": Timestamp::now().as_secs(),
        "expires_at": expiry_unix,
    });
    if let Some(feat) = features_hex {
        content["features_hex"] = serde_json::json!(feat);
    }

    EventBuilder::new(kinds::VOUCH, content.to_string())
        .tag(Tag::identifier(host_pubkey.to_hex()))
        .tag(Tag::public_key(*host_pubkey))
        .tag(Tag::custom(
            TagKind::custom("peer_pubkey"),
            vec![peer_pubkey.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
            vec!["peer".to_string()],
        ))
        .tag(Tag::expiration(Timestamp::from(expiry_unix)))
}

/// Build a vouch-revocation event.
///
/// Kind 38101 with the same d-tag (host pubkey hex) as the original
/// vouch — relays will supersede the prior "active" event with this
/// "revoked" one. Clients MUST check `content.status` before trusting
/// any vouch.
pub fn build_revoke_vouch(
    host_pubkey: &PublicKey,
    reason: &str,
    expiry_unix: u64,
) -> EventBuilder {
    let content = serde_json::json!({
        "status": "revoked",
        "verification_source": "ln_channel",
        "reason": reason,
        "revoked_at": Timestamp::now().as_secs(),
        "expires_at": expiry_unix,
    });

    // The revoke carries the same NIP-40 expiration as a normal vouch
    // so it self-cleans from relays after 30 days. The active vouch it
    // replaced shares the same d-tag, so when this revoke expires the
    // end state is "no attestation at all" — which is what revocation
    // means anyway. Without an expiration tag, revoke events would
    // accumulate forever on relays.
    EventBuilder::new(kinds::VOUCH, content.to_string())
        .tag(Tag::identifier(host_pubkey.to_hex()))
        .tag(Tag::public_key(*host_pubkey))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
            vec!["channel".to_string()],
        ))
        .tag(Tag::expiration(Timestamp::from(expiry_unix)))
}

/// Build an encrypted attestation (join request).
/// The content is NIP-44 encrypted to the host's pubkey by the caller.
pub fn build_attestation(ad_event_id: &EventId, scheme: &str, expiry_unix: u64) -> EventBuilder {
    // Content will be set by the caller after NIP-44 encryption.
    // We build with empty content; the caller replaces it.
    EventBuilder::new(kinds::ATTESTATION, "")
        .tag(Tag::event(*ad_event_id))
        .tag(Tag::custom(
            TagKind::custom("scheme"),
            vec![scheme.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("expiry"),
            vec![expiry_unix.to_string()],
        ))
}

/// Build a seal event. Content is the encrypted manifest.
pub fn build_seal(ad_event_id: &EventId, scheme: &str) -> EventBuilder {
    EventBuilder::new(kinds::SEAL, "")
        .tag(Tag::event(*ad_event_id))
        .tag(Tag::custom(
            TagKind::custom("scheme"),
            vec![scheme.to_string()],
        ))
}

// --- helpers for inspecting fetched vouch events ---

/// True if a fetched kind-38101 event is currently the active form of
/// a vouch: its NIP-40 expiration has not passed AND its content status
/// is `"active"`. A revoked or expired event counts as not active.
pub fn vouch_is_active(event: &Event) -> bool {
    // NIP-40 expiration check
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

    // Content status check
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
