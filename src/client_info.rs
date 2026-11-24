//! `X-MMe-Client-Info` values for Mac anisette identities.
//!
//! Apple's GSA endpoint answers HTTP 503 to any login carrying the client info
//! every public anisette setup has shared for years
//! (`<MacBookPro13,2> <macOS;13.1;22C65> ...`), while other genuine Mac
//! descriptions are accepted. Each identity therefore gets one stable,
//! real model/OS combination picked from [`CANDIDATES`] by its device id, and
//! known-blocked values coming back from remote servers are replaced the same
//! way. Every candidate was checked to reach GSA's authentication stage
//! (HTTP 401 for an empty init rather than 503).
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Values Apple's edge rejects outright (HTTP 503).
pub const BLOCKED: &[&str] = &[
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
    "<MacBookPro15,1> <Mac OS X;10.15.2;19C57> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
];

pub const CANDIDATES: &[&str] = &[
    "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "<MacBookPro14,1> <Mac OS X;10.13.6;17G14042> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "<MacBookPro15,2> <Mac OS X;10.14.6;18G9323> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "<MacBookAir8,1> <Mac OS X;10.14.6;18G103> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "<iMac19,1> <Mac OS X;10.15.7;19H2026> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "<Macmini8,1> <Mac OS X;10.15.7;19H15> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "<MacBookPro16,1> <Mac OS X;10.15.7;19H15> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "<iMac20,1> <Mac OS X;10.15.7;19H2> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
];

/// Stable client info for an identity (seed: its device id).
pub fn for_identity(seed: &str) -> &'static str {
    let digest = Sha256::digest(seed.as_bytes());
    CANDIDATES[digest[0] as usize % CANDIDATES.len()]
}

pub fn is_blocked(value: &str) -> bool {
    BLOCKED.contains(&value.trim())
}

/// Replace a blocked `X-MMe-Client-Info` (any key case) in provider headers,
/// keyed on the headers' own device id so the choice is stable.
pub fn sanitize(headers: &mut HashMap<String, String>) {
    let Some(key) = headers.keys().find(|k| k.eq_ignore_ascii_case("x-mme-client-info")).cloned() else {
        return;
    };
    if !is_blocked(&headers[&key]) {
        return;
    }
    let seed = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-mme-device-id"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    log::debug!("Replacing the client info Apple rejects for device {seed}");
    headers.insert(key, for_identity(&seed).to_owned());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choice_is_stable_and_never_blocked() {
        assert_eq!(for_identity("00006000-ABCDEF"), for_identity("00006000-ABCDEF"));
        for c in CANDIDATES {
            assert!(!is_blocked(c));
        }
    }

    #[test]
    fn sanitize_replaces_only_blocked_values() {
        let mut h = HashMap::from([
            ("X-MMe-Client-Info".to_string(), BLOCKED[0].to_string()),
            ("X-Mme-Device-Id".to_string(), "D1".to_string()),
        ]);
        sanitize(&mut h);
        assert_eq!(h["X-MMe-Client-Info"], for_identity("D1"));

        let mut ok = HashMap::from([("x-mme-client-info".to_string(), "<Custom> <x> <y>".to_string())]);
        sanitize(&mut ok);
        assert_eq!(ok["x-mme-client-info"], "<Custom> <x> <y>");
    }
}
