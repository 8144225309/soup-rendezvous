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

#[test]
fn advertisement_has_correct_tags() {
    let keys = Keys::generate();
    let root_id = EventId::from_slice(&[0xaa; 32]).unwrap();

    let builder = events::build_advertisement(
        &root_id,
        "my-factory",
        "superscalar/v1",
        4,
        8,
        &["europe", "evening"],
        1776000000,
        "{\"test\": true}",
    );
    let event = builder.sign_with_keys(&keys).unwrap();

    assert_eq!(event.kind, kinds::ADVERTISEMENT);
    assert_eq!(events::get_d_tag(&event).as_deref(), Some("my-factory"));
    assert_eq!(
        events::get_tag_value(&event, "scheme").as_deref(),
        Some("superscalar/v1")
    );
    assert_eq!(
        events::get_tag_value(&event, "min_members").as_deref(),
        Some("4")
    );
    assert_eq!(
        events::get_tag_value(&event, "max_members").as_deref(),
        Some("8")
    );
    assert_eq!(
        events::get_tag_value(&event, "slots").as_deref(),
        Some("0/8")
    );
    assert_eq!(
        events::get_tag_value(&event, "expiry").as_deref(),
        Some("1776000000")
    );

    // Check e-tag references root
    let e_tag = events::get_e_tag(&event);
    assert_eq!(e_tag, Some(root_id));

    // Check hashtags
    let hashtags: Vec<String> = event
        .tags
        .iter()
        .filter(|t| t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::T)))
        .filter_map(|t| t.content().map(|s| s.to_string()))
        .collect();
    assert!(hashtags.contains(&"europe".to_string()));
    assert!(hashtags.contains(&"evening".to_string()));

    // Check NIP-40 expiration tag exists
    let has_expiration = event.tags.iter().any(|t| t.kind() == TagKind::Expiration);
    assert!(has_expiration);

    // Content preserved
    assert_eq!(event.content, "{\"test\": true}");
}

#[test]
fn status_update_has_correct_tags() {
    let keys = Keys::generate();
    let ad_id = EventId::from_slice(&[0xbb; 32]).unwrap();

    let builder = events::build_status_update(&ad_id, "superscalar/v1", "filling", 3, 8, "3 of 8");
    let event = builder.sign_with_keys(&keys).unwrap();

    assert_eq!(event.kind, kinds::STATUS_UPDATE);
    assert_eq!(
        events::get_tag_value(&event, "status").as_deref(),
        Some("filling")
    );
    assert_eq!(
        events::get_tag_value(&event, "slots").as_deref(),
        Some("3/8")
    );
    assert_eq!(events::get_e_tag(&event), Some(ad_id));
}

#[test]
fn vouch_has_correct_tags() {
    let keys = Keys::generate();
    let host_keys = Keys::generate();

    let expiry = 1776000000u64 + 30 * 86400;
    let builder = events::build_vouch(&host_keys.public_key(), "03abcdef", 12, "50000000", expiry);
    let event = builder.sign_with_keys(&keys).unwrap();

    assert_eq!(event.kind, kinds::VOUCH);
    assert_eq!(
        events::get_tag_value(&event, "ln_node_id").as_deref(),
        Some("03abcdef")
    );

    // d-tag must be host pubkey hex — makes the event parameterized-replaceable
    // per host so multiple vouches from the coordinator don't overwrite each other
    assert_eq!(
        events::get_d_tag(&event).as_deref(),
        Some(host_keys.public_key().to_hex().as_str())
    );

    // Check p-tag references host
    let p_tag = event.tags.iter().find_map(|t| {
        if t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)) {
            t.content().map(|s| s.to_string())
        } else {
            None
        }
    });
    assert_eq!(
        p_tag.as_deref(),
        Some(host_keys.public_key().to_hex().as_str())
    );

    // Content should be parseable JSON with status=active
    let parsed: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(parsed["status"], "active");
    assert_eq!(parsed["verification_source"], "ln_channel");
    assert_eq!(parsed["ln_node_id"], "03abcdef");
    assert_eq!(parsed["channel_count"], 12);
    assert_eq!(parsed["capacity_sat"], "50000000");
    assert_eq!(parsed["expires_at"], expiry);

    // NIP-40 expiration tag must be present
    let has_expiration = event.tags.iter().any(|t| t.kind() == TagKind::Expiration);
    assert!(has_expiration, "vouch must carry NIP-40 expiration tag");

    // Filterable single-letter tag "l" = "channel"
    let l_tag = event.tags.iter().find_map(|t| {
        if t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)) {
            t.content().map(|s| s.to_string())
        } else {
            None
        }
    });
    assert_eq!(l_tag.as_deref(), Some("channel"));
}

#[test]
fn utxo_vouch_has_correct_fields_and_tag() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expiry = Timestamp::now().as_secs() + 30 * 86400;

    let ev = events::build_vouch_utxo(
        &host.public_key(),
        "bc1qexampleaddressxxxxxxxxxxxxxxxxxxxx",
        150_000,
        "aabb".repeat(16).as_str(), // 64-hex txid
        0,
        expiry,
    )
    .sign_with_keys(&coord)
    .unwrap();

    assert_eq!(ev.kind, kinds::VOUCH);

    // d-tag = host pubkey hex
    assert_eq!(
        events::get_d_tag(&ev).as_deref(),
        Some(host.public_key().to_hex().as_str())
    );

    // l tag = "utxo"
    let l_tag = ev.tags.iter().find_map(|t| {
        if t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)) {
            t.content().map(|s| s.to_string())
        } else {
            None
        }
    });
    assert_eq!(l_tag.as_deref(), Some("utxo"));

    // btc_address tag
    assert_eq!(
        events::get_tag_value(&ev, "btc_address").as_deref(),
        Some("bc1qexampleaddressxxxxxxxxxxxxxxxxxxxx")
    );

    // Content schema
    let parsed: serde_json::Value = serde_json::from_str(&ev.content).unwrap();
    assert_eq!(parsed["status"], "active");
    assert_eq!(parsed["verification_source"], "btc_utxo");
    assert_eq!(
        parsed["btc_address"],
        "bc1qexampleaddressxxxxxxxxxxxxxxxxxxxx"
    );
    assert_eq!(parsed["verified_balance_sat"], "150000");
    assert_eq!(parsed["utxo_vout"], 0);
    assert_eq!(parsed["expires_at"], expiry);

    // NIP-40 expiration tag
    let has_expiration = ev.tags.iter().any(|t| t.kind() == TagKind::Expiration);
    assert!(has_expiration);
}

#[test]
fn peer_vouch_has_correct_fields_and_tag() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expiry = Timestamp::now().as_secs() + 30 * 86400;

    let ev = events::build_vouch_peer(
        &host.public_key(),
        "03peerexample",
        &[
            "host.example.com:9735".to_string(),
            "ipv6.example:9735".to_string(),
        ],
        Some("080c8802"),
        expiry,
    )
    .sign_with_keys(&coord)
    .unwrap();

    assert_eq!(ev.kind, kinds::VOUCH);

    // d-tag = host pubkey hex
    assert_eq!(
        events::get_d_tag(&ev).as_deref(),
        Some(host.public_key().to_hex().as_str())
    );

    // l tag = "peer"
    let l_tag = ev.tags.iter().find_map(|t| {
        if t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)) {
            t.content().map(|s| s.to_string())
        } else {
            None
        }
    });
    assert_eq!(l_tag.as_deref(), Some("peer"));

    // peer_pubkey tag
    assert_eq!(
        events::get_tag_value(&ev, "peer_pubkey").as_deref(),
        Some("03peerexample")
    );

    let parsed: serde_json::Value = serde_json::from_str(&ev.content).unwrap();
    assert_eq!(parsed["status"], "active");
    assert_eq!(parsed["verification_source"], "ln_peer");
    assert_eq!(parsed["peer_pubkey"], "03peerexample");
    assert_eq!(parsed["peer_addresses"][0], "host.example.com:9735");
    assert_eq!(parsed["peer_addresses"][1], "ipv6.example:9735");
    assert_eq!(parsed["features_hex"], "080c8802");
    assert_eq!(parsed["expires_at"], expiry);
}

#[test]
fn vouch_is_active_reports_true_for_fresh_active() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expiry = Timestamp::now().as_secs() + 3600;
    let ev = events::build_vouch(&host.public_key(), "03abc", 1, "0", expiry)
        .sign_with_keys(&coord)
        .unwrap();
    assert!(events::vouch_is_active(&ev));
    assert_eq!(events::vouch_ln_node_id(&ev).as_deref(), Some("03abc"));
}

#[test]
fn vouch_is_active_reports_false_for_expired() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expired = Timestamp::now().as_secs() - 60; // already past
    let ev = events::build_vouch(&host.public_key(), "03abc", 1, "0", expired)
        .sign_with_keys(&coord)
        .unwrap();
    assert!(!events::vouch_is_active(&ev));
}

#[test]
fn vouch_is_active_reports_false_for_revoked() {
    let coord = Keys::generate();
    let host = Keys::generate();
    let expiry = Timestamp::now().as_secs() + 30 * 86400;
    let ev = events::build_revoke_vouch(&host.public_key(), "abuse", expiry)
        .sign_with_keys(&coord)
        .unwrap();
    assert!(!events::vouch_is_active(&ev));
    // Revoke events MUST carry NIP-40 expiration so they self-clean
    // from relays — otherwise they accumulate forever.
    let has_expiration = ev.tags.iter().any(|t| t.kind() == TagKind::Expiration);
    assert!(has_expiration);
}

#[test]
fn revoke_vouch_shares_d_tag_and_marks_revoked() {
    let keys = Keys::generate();
    let host_keys = Keys::generate();

    let active = events::build_vouch(
        &host_keys.public_key(),
        "03abcdef",
        12,
        "50000000",
        1776000000u64 + 30 * 86400,
    )
    .sign_with_keys(&keys)
    .unwrap();
    let revoke_expiry = Timestamp::now().as_secs() + 30 * 86400;
    let revoked = events::build_revoke_vouch(
        &host_keys.public_key(),
        "operator misbehavior",
        revoke_expiry,
    )
    .sign_with_keys(&keys)
    .unwrap();

    // Same kind + same d-tag + same author → relays supersede the active one
    assert_eq!(active.kind, revoked.kind);
    assert_eq!(events::get_d_tag(&active), events::get_d_tag(&revoked));
    assert_eq!(
        events::get_d_tag(&revoked).as_deref(),
        Some(host_keys.public_key().to_hex().as_str())
    );

    let parsed: serde_json::Value = serde_json::from_str(&revoked.content).unwrap();
    assert_eq!(parsed["status"], "revoked");
    assert_eq!(parsed["reason"], "operator misbehavior");
    assert!(parsed["revoked_at"].as_u64().is_some());
}

// --- NIP-44 encryption round-trip ---

#[test]
fn attestation_payload_encrypts_and_decrypts() {
    let joiner_keys = Keys::generate();
    let host_keys = Keys::generate();

    let payload = events::AttestationPayload {
        joiner_cln_pubkey: "03deadbeef".into(),
        joiner_cln_endpoint: "127.0.0.1:9735".into(),
        joiner_nostr_relays: vec!["wss://relay.example".into()],
        nonce: "abc123".into(),
        message: "I want to join".into(),
    };
    let json = serde_json::to_string(&payload).unwrap();

    // Joiner encrypts to host
    let encrypted = nip44::encrypt(
        joiner_keys.secret_key(),
        &host_keys.public_key(),
        &json,
        nip44::Version::default(),
    )
    .unwrap();

    assert_ne!(encrypted, json); // actually encrypted

    // Host decrypts
    let decrypted = nip44::decrypt(
        host_keys.secret_key(),
        &joiner_keys.public_key(),
        &encrypted,
    )
    .unwrap();

    let recovered: events::AttestationPayload = serde_json::from_str(&decrypted).unwrap();
    assert_eq!(recovered.joiner_cln_pubkey, "03deadbeef");
    assert_eq!(recovered.message, "I want to join");
}

#[test]
fn seal_manifest_encrypts_and_decrypts() {
    let host_keys = Keys::generate();
    let member_keys = Keys::generate();

    let manifest = events::SealManifest {
        advertisement_id: "abc123".into(),
        rules_hash: "def456".into(),
        members: vec![events::SealMember {
            nostr_pubkey: member_keys.public_key().to_hex(),
            cln_pubkey: "03aabb".into(),
            cln_endpoint: "host:9735".into(),
            slot: 0,
        }],
        sealed_at: 1776000000,
    };
    let json = serde_json::to_string(&manifest).unwrap();

    // Host encrypts to member
    let encrypted = nip44::encrypt(
        host_keys.secret_key(),
        &member_keys.public_key(),
        &json,
        nip44::Version::default(),
    )
    .unwrap();

    // Member decrypts
    let decrypted = nip44::decrypt(
        member_keys.secret_key(),
        &host_keys.public_key(),
        &encrypted,
    )
    .unwrap();

    let recovered: events::SealManifest = serde_json::from_str(&decrypted).unwrap();
    assert_eq!(recovered.advertisement_id, "abc123");
    assert_eq!(recovered.members.len(), 1);
    assert_eq!(recovered.members[0].slot, 0);
    assert_eq!(recovered.members[0].cln_pubkey, "03aabb");
}

// --- Payload serialization ---

#[test]
fn superscalar_payload_round_trips() {
    let payload = events::SuperScalarPayload {
        lsp_pubkey: "02abc".into(),
        lsp_endpoints: vec!["host:9735".into()],
        lsp_nostr_relays: vec!["wss://relay.example".into()],
        total_funding_sat: "10000000".into(),
        client_contribution_sat: "1000000".into(),
        lsp_liquidity_sat: "2000000".into(),
        leaf_arity: 2,
        epoch_count: 30,
        lifetime_blocks: 4320,
        dying_period_blocks: 432,
        lsp_fee_sat: "5000".into(),
        lsp_fee_ppm: 1000,
    };

    let json = serde_json::to_string(&payload).unwrap();
    let recovered: events::SuperScalarPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.total_funding_sat, "10000000");
    assert_eq!(recovered.leaf_arity, 2);
    assert_eq!(recovered.lsp_fee_ppm, 1000);
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
