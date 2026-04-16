//! Event builders for the three-phase coordination protocol.
//!
//! Each function constructs a Nostr event with the correct kind, tags,
//! and content for its role in the advertise / attest / seal lifecycle.

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

/// Build the coordinator's root discovery thread event.
/// This is a long-lived addressable event that factory advertisements
/// reply to.
pub fn build_root_thread(description: &str) -> EventBuilder {
    EventBuilder::new(kinds::ADVERTISEMENT, description).tag(Tag::identifier("root"))
}

/// Build a factory advertisement event.
/// Replies to the coordinator's root thread via an e-tag.
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
        ));

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

/// Build a vouch event — coordinator attesting that a host proved
/// control of an LN node.
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
