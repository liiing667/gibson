//! Canonical identity for addresses, hosts, and shared sets.
//!
//! Everything the server correlates — sessions, shared-IP sets, pattern
//! groups — keys on these canonical forms instead of raw strings, so the
//! same endpoint or machine always lands in the same identity bucket:
//!
//! * Addresses: IPv4-mapped IPv6 (`::ffff:a.b.c.d`) folds into the plain
//!   IPv4 identity; textual variants of one address compare equal.
//! * Hosts: case and a trailing root dot are presentation details of the
//!   same machine name.  Matching is deliberately *exact* after this
//!   normalisation — no fuzzy or first-label matching — so a forged
//!   lookalike name can never merge into another machine's identity.

use std::net::IpAddr;

/// Canonical form of an IP address.
///
/// An IPv4-mapped IPv6 address is the *same endpoint* as the plain IPv4
/// address — dual-stack collectors report either form depending on the
/// socket family — so it folds into the IPv4 identity.
pub fn canonical_addr(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Parse a string into its canonical address identity.
/// Returns `None` when the string is not an IP address at all.
pub fn canonical_ip(raw: &str) -> Option<IpAddr> {
    raw.trim().parse::<IpAddr>().ok().map(canonical_addr)
}

/// Canonical string key for an IP-bearing field.
///
/// Parseable addresses get the canonical form; anything else is returned
/// trimmed so malformed data still groups deterministically instead of
/// scattering across whitespace variants.
pub fn canonical_ip_key(raw: &str) -> String {
    match canonical_ip(raw) {
        Some(addr) => addr.to_string(),
        None => raw.trim().to_string(),
    }
}

/// Canonical identity for a machine hostname.
///
/// DNS names are case-insensitive and a trailing root dot (`host.` vs
/// `host`) denotes the same name, so both are normalised.  Nothing else is
/// — `web-01` and `web-01.corp.example` stay distinct identities, because
/// merging them would let a forged domain suffix hijack another machine's
/// session.
pub fn canonical_host_key(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_lowercase()
}

/// Canonical form of a DNS name (e.g. a record's `remote_hostname`) for
/// suffix matching.  Reverse-DNS answers frequently carry the root dot.
pub fn canonical_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

/// True when the address is not publicly routable and therefore has no
/// public ownership identity (ARIN/ASN) and no cloud provider.
///
/// Checked on the *canonical* address, so an IPv4-mapped private address
/// like `::ffff:10.0.0.1` is recognised as private instead of slipping
/// through the IPv6 branch of an address-family check.
pub fn is_non_public(addr: &IpAddr) -> bool {
    match canonical_addr(*addr) {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_link_local() || v4.is_loopback() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_mapped_ipv6_folds_into_ipv4_identity() {
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        let plain: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(canonical_addr(mapped), plain);
        assert_eq!(
            canonical_ip("::ffff:203.0.113.7").unwrap().to_string(),
            "203.0.113.7"
        );
    }

    #[test]
    fn textual_variants_share_one_key() {
        assert_eq!(
            canonical_ip_key("2001:DB8:0:0::1"),
            canonical_ip_key("2001:db8::1")
        );
        assert_eq!(canonical_ip_key("  203.0.113.7 "), "203.0.113.7");
        // Unparseable input still gets a deterministic key.
        assert_eq!(canonical_ip_key(" not-an-ip "), "not-an-ip");
    }

    #[test]
    fn host_key_normalises_case_and_root_dot_only() {
        assert_eq!(canonical_host_key("WebServer"), "webserver");
        assert_eq!(canonical_host_key("WEBSERVER."), "webserver");
        assert_eq!(canonical_host_key(" webserver "), "webserver");
        // Lookalikes must NOT merge — forged names stay separate.
        assert_ne!(canonical_host_key("web-01"), canonical_host_key("web-01.corp.example"));
        assert_ne!(canonical_host_key("web-01"), canonical_host_key("web_01"));
    }

    #[test]
    fn dns_name_strips_root_dot_and_case() {
        assert_eq!(canonical_dns_name("Ec2-1-2-3-4.AmazonAWS.com."), "ec2-1-2-3-4.amazonaws.com");
    }

    #[test]
    fn non_public_covers_mapped_and_v6_private() {
        // IPv4-mapped private must be recognised as private.
        assert!(is_non_public(&"::ffff:10.0.0.9".parse().unwrap()));
        assert!(is_non_public(&"::ffff:169.254.0.1".parse().unwrap()));
        assert!(is_non_public(&"10.0.0.9".parse().unwrap()));
        assert!(is_non_public(&"192.168.1.1".parse().unwrap()));
        assert!(is_non_public(&"127.0.0.1".parse().unwrap()));
        assert!(is_non_public(&"::1".parse().unwrap()));
        assert!(is_non_public(&"fc00::1".parse().unwrap())); // ULA
        assert!(is_non_public(&"fe80::1".parse().unwrap())); // link-local
        assert!(!is_non_public(&"203.0.113.7".parse().unwrap()));
        assert!(!is_non_public(&"2606:4700::1111".parse().unwrap()));
    }
}
