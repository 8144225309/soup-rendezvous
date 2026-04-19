//! Nostr event kind numbers for soup-rendezvous.
//!
//! All kinds are in the experimental range (38000-38999). A future NIP
//! submission would register them formally.

use nostr_sdk::Kind;

/// Coordinator root thread. Addressable event (NIP-33 parameterized
/// replaceable, d-tag `"root"`) — republishing replaces the prior
/// version on relays. Separates the coordinator's identity post from
/// factory advertisements so clients can filter cleanly.
pub const ROOT_THREAD: Kind = Kind::Custom(38099);

/// Factory advertisement. Addressable event (NIP-33 parameterized
/// replaceable) — the host can update it by publishing a new event
/// with the same d-tag (cohort name).
pub const ADVERTISEMENT: Kind = Kind::Custom(38100);

/// Coordinator vouch. Public attestation that a host proved control
/// of a specific LN node.
pub const VOUCH: Kind = Kind::Custom(38101);

/// Factory status update. Public event showing current fill status,
/// activity feed messages. Regular event (not replaceable) so updates
/// form a timeline.
pub const STATUS_UPDATE: Kind = Kind::Custom(38102);

/// Join attestation. Content is NIP-44 encrypted to the host.
pub const ATTESTATION: Kind = Kind::Custom(38200);

/// Sealed cohort manifest. Content is NIP-44 encrypted to each member.
pub const SEAL: Kind = Kind::Custom(38300);
