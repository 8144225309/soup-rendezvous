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
pub fn build_root_thread(description: &str) -> EventBuilder {
    EventBuilder::new(kinds::ADVERTISEMENT, description).tag(Tag::identifier("root"))
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
pub fn build_vouch(
    host_pubkey: &PublicKey,
    ln_node_id: &str,
    channel_count: u32,
    capacity_sat: &str,
) -> EventBuilder {
    let content = serde_json::json!({
        "ln_node_id": ln_node_id,
        "channel_count": channel_count,
        "capacity_sat": capacity_sat,
        "verified_at": Timestamp::now().as_secs(),
    });

    EventBuilder::new(kinds::VOUCH, content.to_string())
        .tag(Tag::public_key(*host_pubkey))
        .tag(Tag::custom(
            TagKind::custom("ln_node_id"),
            vec![ln_node_id.to_string()],
        ))
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
