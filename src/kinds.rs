//! Nostr event kind numbers for soup-rendezvous.
//!
//! The protocol deliberately uses only three kinds. Everything else about
//! factory state (parameters, capacity, slots, join flow, seal, signing)
//! happens LSP-to-wallet over Lightning — Nostr is pure discovery.
//!
//! All kinds are in the experimental range (38000-38999). A future NIP
//! submission would register them formally.

use nostr_sdk::Kind;

/// Coordinator root thread. Addressable event (NIP-33 parameterized
/// replaceable, d-tag `"root"`) — republishing replaces the prior
/// version on relays. Carries the coordinator's human-readable
/// description; the coordinator's npub is the durable identity.
pub const ROOT_THREAD: Kind = Kind::Custom(38099);

/// Coordinator vouch — one entry in the public seed list of verified
/// LSP contact pointers. Parameterized-replaceable with d-tag equal to
/// the host's Nostr pubkey hex. NIP-40 expiration tag caps lifetime.
pub const VOUCH: Kind = Kind::Custom(38101);
