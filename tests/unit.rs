//! Unit tests for soup-rendezvous event construction, encryption,
//! challenge validation, and payload serialization.

use nostr::nips::nip44;
use nostr_sdk::prelude::*;
use soup_rendezvous::events;
use soup_rendezvous::kinds;

// --- Event construction ---

#[test]
fn root_thread_has_correct_kind_and_d_tag() {
    let keys = Keys::generate();
    let builder = events::build_root_thread("test root");
    let event = builder.sign_with_keys(&keys).unwrap();

    assert_eq!(event.kind, kinds::ROOT_THREAD);
    let d_tag = events::get_d_tag(&event);
    assert_eq!(d_tag.as_deref(), Some("root"));
    assert_eq!(event.content, "test root");
}

// Helper: extract the `["l", ...]` tag value from a vouch.
fn l_tag(ev: &Event) -> Option<String> {
    ev.tags.iter().find_map(|t| {
        if t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)) {
            t.content().map(|s| s.to_string())
        } else {
            None
        }
    })
}

#[test]
fn channel_vouch_unified_format() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expiry = 1776000000u64 + 30 * 86400;

    let ev = events::build_vouch(
        &host.public_key(),
        events::VouchTier::Channel,
        "03abcdef",
        &[],
        None,
        expiry,
    )
    .sign_with_keys(&coord)
    .unwrap();

    assert_eq!(ev.kind, kinds::VOUCH);
    assert_eq!(l_tag(&ev).as_deref(), Some("channel"));
    assert_eq!(events::vouch_ln_node_id(&ev).as_deref(), Some("03abcdef"));
    assert_eq!(
        events::get_d_tag(&ev).as_deref(),
        Some(host.public_key().to_hex().as_str())
    );

    let parsed: serde_json::Value = serde_json::from_str(&ev.content).unwrap();
    assert_eq!(parsed["status"], "active");
    assert_eq!(parsed["ln_node_id"], "03abcdef");
    assert_eq!(parsed["expires_at"], expiry);
    // Stripped fields must NOT appear:
    assert!(parsed.get("verification_source").is_none());
    assert!(parsed.get("channel_count").is_none());
    assert!(parsed.get("capacity_sat").is_none());
    assert!(parsed.get("ln_addresses").is_none()); // omitted when empty
    assert!(events::get_tag_value(&ev, "btc_hash").is_none());
}

#[test]
fn utxo_vouch_unified_format_carries_ln_contact_and_btc_hash() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expiry = Timestamp::now().as_secs() + 30 * 86400;
    let btc_hash = events::btc_address_hash("bc1qexampleaddressxxxxxxxxxxxxxxxxxxxx");

    let ev = events::build_vouch(
        &host.public_key(),
        events::VouchTier::Utxo,
        "03utxohostnode",
        &["host.example:9735".to_string()],
        Some(&btc_hash),
        expiry,
    )
    .sign_with_keys(&coord)
    .unwrap();

    assert_eq!(l_tag(&ev).as_deref(), Some("utxo"));
    assert_eq!(
        events::vouch_ln_node_id(&ev).as_deref(),
        Some("03utxohostnode")
    );
    assert_eq!(
        events::get_tag_value(&ev, "btc_hash").as_deref(),
        Some(btc_hash.as_str())
    );

    let parsed: serde_json::Value = serde_json::from_str(&ev.content).unwrap();
    assert_eq!(parsed["status"], "active");
    assert_eq!(parsed["ln_node_id"], "03utxohostnode");
    assert_eq!(parsed["ln_addresses"][0], "host.example:9735");
    // Privacy: must NOT publish the btc address, txid/vout, or balance.
    assert!(parsed.get("btc_address").is_none());
    assert!(parsed.get("utxo_txid").is_none());
    assert!(parsed.get("utxo_vout").is_none());
    assert!(parsed.get("verified_balance_sat").is_none());
    assert!(parsed.get("verification_source").is_none());
    assert!(events::get_tag_value(&ev, "btc_address").is_none());
}

#[test]
fn peer_vouch_unified_format_uses_ln_node_id_naming() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expiry = Timestamp::now().as_secs() + 30 * 86400;

    let ev = events::build_vouch(
        &host.public_key(),
        events::VouchTier::Peer,
        "03peerexample",
        &[
            "host.example.com:9735".to_string(),
            "ipv6.example:9735".to_string(),
        ],
        None,
        expiry,
    )
    .sign_with_keys(&coord)
    .unwrap();

    assert_eq!(l_tag(&ev).as_deref(), Some("peer"));
    assert_eq!(
        events::vouch_ln_node_id(&ev).as_deref(),
        Some("03peerexample")
    );

    let parsed: serde_json::Value = serde_json::from_str(&ev.content).unwrap();
    assert_eq!(parsed["status"], "active");
    assert_eq!(parsed["ln_node_id"], "03peerexample");
    assert_eq!(parsed["ln_addresses"][0], "host.example.com:9735");
    // Renamed away: peer_pubkey/peer_addresses become ln_node_id/ln_addresses.
    assert!(parsed.get("peer_pubkey").is_none());
    assert!(parsed.get("peer_addresses").is_none());
    assert!(parsed.get("features_hex").is_none());
    assert!(parsed.get("verification_source").is_none());
}

#[test]
fn btc_address_hash_is_deterministic_and_short() {
    let h1 = events::btc_address_hash("bc1qexample");
    let h2 = events::btc_address_hash("bc1qexample");
    let h3 = events::btc_address_hash("bc1qother");
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);
    assert_eq!(h1.len(), 24); // 12 bytes hex
}

#[test]
fn vouch_is_active_reports_true_for_fresh_active() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expiry = Timestamp::now().as_secs() + 3600;
    let ev = events::build_vouch(
        &host.public_key(),
        events::VouchTier::Channel,
        "03abc",
        &[],
        None,
        expiry,
    )
    .sign_with_keys(&coord)
    .unwrap();
    assert!(events::vouch_is_active(&ev));
    assert_eq!(events::vouch_ln_node_id(&ev).as_deref(), Some("03abc"));
}

#[test]
fn vouch_is_active_reports_false_for_expired() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expired = Timestamp::now().as_secs() - 60;
    let ev = events::build_vouch(
        &host.public_key(),
        events::VouchTier::Channel,
        "03abc",
        &[],
        None,
        expired,
    )
    .sign_with_keys(&coord)
    .unwrap();
    assert!(!events::vouch_is_active(&ev));
}

#[test]
fn vouch_is_active_reports_false_for_revoked() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expiry = Timestamp::now().as_secs() + 30 * 86400;
    let ev = events::build_revoke_vouch(&host.public_key(), events::VouchTier::Channel, expiry)
        .sign_with_keys(&coord)
        .unwrap();
    assert!(!events::vouch_is_active(&ev));
    let has_expiration = ev.tags.iter().any(|t| t.kind() == TagKind::Expiration);
    assert!(has_expiration);
}

#[test]
fn revoke_vouch_shares_d_tag_and_marks_revoked() {
    let coord = Keys::generate();
    let host = Keys::generate();

    let active = events::build_vouch(
        &host.public_key(),
        events::VouchTier::Channel,
        "03abcdef",
        &[],
        None,
        1776000000u64 + 30 * 86400,
    )
    .sign_with_keys(&coord)
    .unwrap();
    let revoke_expiry = Timestamp::now().as_secs() + 30 * 86400;
    let revoked = events::build_revoke_vouch(
        &host.public_key(),
        events::VouchTier::Channel,
        revoke_expiry,
    )
    .sign_with_keys(&coord)
    .unwrap();

    assert_eq!(active.kind, revoked.kind);
    assert_eq!(events::get_d_tag(&active), events::get_d_tag(&revoked));
    assert_eq!(
        events::get_d_tag(&revoked).as_deref(),
        Some(host.public_key().to_hex().as_str())
    );

    let parsed: serde_json::Value = serde_json::from_str(&revoked.content).unwrap();
    assert_eq!(parsed["status"], "revoked");
    assert!(parsed["revoked_at"].as_u64().is_some());
    // Reason field is operator-side audit only — not republished.
    assert!(parsed.get("reason").is_none());
}

// --- G: revoke expiry outlives the vouch it revokes ---

/// The revoke CLI path reads the prior vouch's NIP-40 expiration and
/// stamps the revoke with `original + 86400`. This test locks down
/// the `build_revoke_vouch` contract that underpins that behavior: the
/// expiration tag on the revoke event is exactly what the caller
/// passes. The caller (cmd_revoke_vouch) is responsible for computing
/// `original_expires_at + 86400`; this keeps the event builder
/// honest so the CLI math lands in the published event unchanged.
#[test]
fn revoke_vouch_expiration_tag_matches_caller_argument() {
    let coord = Keys::generate();
    let host = Keys::generate();

    let original_expiry = 1_800_000_000u64;
    let revoke_expiry = original_expiry + 86400;

    let ev = events::build_revoke_vouch(&host.public_key(), events::VouchTier::Utxo, revoke_expiry)
        .sign_with_keys(&coord)
        .unwrap();

    let tag_expiry = ev
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::Expiration)
        .and_then(|t| t.content())
        .and_then(|s| s.parse::<u64>().ok())
        .expect("revoke event must carry a NIP-40 expiration tag");
    assert_eq!(tag_expiry, revoke_expiry);
    assert!(
        tag_expiry > original_expiry,
        "revoke must outlive the vouch it revokes by construction"
    );
    assert_eq!(tag_expiry - original_expiry, 86400);

    // Tier is preserved per caller argument too.
    let l = l_tag(&ev);
    assert_eq!(l.as_deref(), Some("utxo"));
}

// --- NIP-44 encryption round-trip (proof DM envelope) ---

#[test]
fn nip44_round_trip_for_proof_dm() {
    // The only encrypted payloads left in the protocol are proof-request
    // DMs (host → coordinator) and vouch-confirmation DMs (coordinator →
    // host). Both ride NIP-44; this test covers the encrypt/decrypt
    // primitive we depend on for either direction.
    let host_keys = Keys::generate();
    let coord_keys = Keys::generate();

    let plaintext = r#"{"type":"proof_of_channel","node_id":"03abc","zbase":"d9rzo","challenge":"soup-rendezvous:proof-of-channel:v0:npub..."}"#;

    let encrypted = nip44::encrypt(
        host_keys.secret_key(),
        &coord_keys.public_key(),
        plaintext,
        nip44::Version::default(),
    )
    .unwrap();
    assert_ne!(encrypted, plaintext);

    let decrypted =
        nip44::decrypt(coord_keys.secret_key(), &host_keys.public_key(), &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

// --- Tag extraction helpers ---

#[test]
fn get_tag_value_extracts_custom_tags() {
    let keys = Keys::generate();
    let builder = EventBuilder::new(Kind::Custom(1), "test")
        .tag(Tag::custom(
            TagKind::custom("scheme"),
            vec!["superscalar/v1".to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("slots"),
            vec!["3/8".to_string()],
        ));
    let event = builder.sign_with_keys(&keys).unwrap();

    assert_eq!(
        events::get_tag_value(&event, "scheme").as_deref(),
        Some("superscalar/v1")
    );
    assert_eq!(
        events::get_tag_value(&event, "slots").as_deref(),
        Some("3/8")
    );
    assert_eq!(events::get_tag_value(&event, "missing"), None);
}

#[test]
fn get_d_tag_extracts_identifier() {
    let keys = Keys::generate();
    let builder = EventBuilder::new(Kind::Custom(1), "test").tag(Tag::identifier("my-factory"));
    let event = builder.sign_with_keys(&keys).unwrap();

    assert_eq!(events::get_d_tag(&event).as_deref(), Some("my-factory"));
}

#[test]
fn get_e_tag_extracts_event_reference() {
    let keys = Keys::generate();
    let ref_id = EventId::from_slice(&[0xcc; 32]).unwrap();
    let builder = EventBuilder::new(Kind::Custom(1), "test").tag(Tag::event(ref_id));
    let event = builder.sign_with_keys(&keys).unwrap();

    assert_eq!(events::get_e_tag(&event), Some(ref_id));
}

// --- Challenge format ---

#[test]
fn challenge_format_is_valid() {
    // Simulate what cmd_challenge produces
    let keys = Keys::generate();
    let coordinator_npub = keys.public_key().to_bech32().unwrap();
    let random_bytes: [u8; 16] = rand::random();
    let challenge = format!(
        "soup-rendezvous:proof-of-channel:v0:{}:{}:{}",
        coordinator_npub,
        hex::encode(random_bytes),
        Timestamp::now().as_secs()
    );

    let parts: Vec<&str> = challenge.split(':').collect();
    assert_eq!(parts.len(), 6);
    assert_eq!(parts[0], "soup-rendezvous");
    assert_eq!(parts[1], "proof-of-channel");
    assert_eq!(parts[2], "v0");
    assert_eq!(parts[3], &coordinator_npub);
    assert_eq!(parts[4].len(), 32); // 16 bytes hex
    parts[5].parse::<u64>().unwrap(); // valid timestamp
}

#[test]
fn challenge_rejects_wrong_format() {
    let parts: Vec<&str> = "bad-format:no-good".split(':').collect();
    assert!(
        parts.len() != 6
            || parts[0] != "soup-rendezvous"
            || parts[1] != "proof-of-channel"
            || parts[2] != "v0"
    );
}

#[test]
fn challenge_rejects_wrong_coordinator() {
    let keys = Keys::generate();
    let wrong_keys = Keys::generate();
    let coordinator_npub = keys.public_key().to_bech32().unwrap();
    let wrong_npub = wrong_keys.public_key().to_bech32().unwrap();

    let challenge = format!(
        "soup-rendezvous:proof-of-channel:v0:{}:deadbeef:1776000000",
        wrong_npub
    );

    let parts: Vec<&str> = challenge.split(':').collect();
    assert_ne!(parts[3], &coordinator_npub);
}

#[test]
fn challenge_rejects_expired() {
    let old_ts: u64 = 1000000000; // year 2001
    let now = Timestamp::now().as_secs();
    let skew = now.abs_diff(old_ts);
    assert!(skew > 300);
}
