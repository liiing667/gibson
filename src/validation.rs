//! Semantic validation for connection records.
//!
//! JSON deserialisation only proves that a payload is well-formed.  A record
//! whose `remote_ip` is not an IP, whose port is 0, whose PID is 0, whose
//! protocol is something other than TCP/UDP, or whose IPv4/IPv6 families
//! contradict each other still deserialises happily — and previously flowed
//! straight into sessions, where it poisoned cloud attribution and anomaly
//! detection.
//!
//! [`validate_record`] is the single gate every record must pass before it is
//! appended to a session.  Optional fields that are legitimately absent
//! (`local_port`, `remote_hostname`, `state`, `ppid`, `command_line`, ...)
//! stay `None` and always pass; only present-but-contradictory values fail.

use std::net::IpAddr;

use crate::collector_v2::ConnectionRecord;

/// Split a `host:port` endpoint into its components.
///
/// Handles both collector-produced shapes:
///   * `203.0.113.7:443`        (IPv4)
///   * `[2001:db8::1]:443`      (IPv6, RFC 5952 bracketed)
fn parse_host_port(endpoint: &str) -> Option<(IpAddr, u16)> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        let close = rest.find(']')?;
        let ip: IpAddr = rest[..close].parse().ok()?;
        let port: u16 = rest[close + 1..].strip_prefix(':')?.parse().ok()?;
        return Some((ip, port));
    }

    let (host, port) = endpoint.rsplit_once(':')?;
    Some((host.parse::<IpAddr>().ok()?, port.parse::<u16>().ok()?))
}

/// Validate one record.  Returns `Err(reason)` describing the first
/// contradiction found, or `Ok(())` when the record is safe to append.
pub fn validate_record(r: &ConnectionRecord) -> Result<(), String> {
    validate_connection_fields(
        r.pid,
        &r.process_name,
        &r.protocol,
        &r.remote_ip,
        r.remote_port,
        r.remote_hostname.as_deref(),
    )?;

    // ── addresses must be real, bare IPs ───────────────────────────────────
    let remote_ip: IpAddr = r
        .remote_ip
        .parse()
        .expect("remote_ip validated by validate_connection_fields");
    let local_ip: IpAddr = r.local_addr.parse().map_err(|_| {
        format!(
            "local_addr {:?} is not a bare IP address (no port allowed)",
            r.local_addr
        )
    })?;

    // ── address families must agree across the connection ──────────────────
    if remote_ip.is_ipv4() != local_ip.is_ipv4() {
        return Err(format!(
            "address family mismatch: remote_ip {} is {} but local_addr {} is {}",
            r.remote_ip,
            if remote_ip.is_ipv4() { "IPv4" } else { "IPv6" },
            r.local_addr,
            if local_ip.is_ipv4() { "IPv4" } else { "IPv6" }
        ));
    }

    if let Some(0) = r.local_port {
        return Err("local_port must be between 1 and 65535 (got 0)".to_string());
    }

    // remote_port presence/range was checked above; unwrap for the cross-check.
    let remote_port = r.remote_port.expect("remote_port validated above");

    // ── remote_addr must be host:port and agree with the split fields ──────
    match parse_host_port(&r.remote_addr) {
        Some((addr_ip, addr_port)) => {
            if addr_ip != remote_ip {
                return Err(format!(
                    "remote_addr {:?} contradicts remote_ip {:?}",
                    r.remote_addr, r.remote_ip
                ));
            }
            if addr_port != remote_port {
                return Err(format!(
                    "remote_addr {:?} contradicts remote_port {}",
                    r.remote_addr, remote_port
                ));
            }
        }
        None => {
            return Err(format!(
                "remote_addr {:?} must be an ip:port endpoint matching remote_ip/remote_port",
                r.remote_addr
            ))
        }
    }

    Ok(())
}

/// Validate the fields available in every record representation, including
/// the reduced JSONL struct used by the offline parser.  Every check that does
/// not need `local_addr`/`remote_addr` lives here so both ingestion paths share
/// exactly one rule set for their common fields.
pub fn validate_connection_fields(
    pid: u32,
    process_name: &str,
    protocol: &str,
    remote_ip: &str,
    remote_port: Option<u16>,
    remote_hostname: Option<&str>,
) -> Result<(), String> {
    // ── scalar fields ──────────────────────────────────────────────────────
    if process_name.trim().is_empty() {
        return Err("process_name must not be empty".to_string());
    }
    if pid == 0 {
        return Err("pid must be a non-zero process id".to_string());
    }
    match protocol.to_ascii_uppercase().as_str() {
        "TCP" | "UDP" => {}
        other => {
            return Err(format!(
                "unsupported protocol {other:?}: expected \"TCP\" or \"UDP\""
            ))
        }
    }

    // ── address must be a real, bare IP ────────────────────────────────────
    let _: IpAddr = remote_ip
        .parse()
        .map_err(|_| format!("remote_ip {remote_ip:?} is not a valid IP address"))?;

    // ── ports: remote is required, local is optional but must be valid ─────
    match remote_port {
        Some(p) if p > 0 => p,
        Some(_) => {
            return Err("remote_port must be between 1 and 65535 (got 0)".to_string())
        }
        None => return Err("remote_port is required for a connection record".to_string()),
    };

    // ── optional hostname: null is fine, an empty string is not ────────────
    if let Some(host) = remote_hostname {
        if host.trim().is_empty() {
            return Err(
                "remote_hostname must not be an empty string; use null when absent"
                    .to_string(),
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn base_record() -> ConnectionRecord {
        ConnectionRecord {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            pid: 4242,
            process_name: "nc.exe".to_string(),
            protocol: "TCP".to_string(),
            local_addr: "10.0.0.5".to_string(),
            local_port: Some(49152),
            remote_addr: "203.0.113.7:443".to_string(),
            remote_port: Some(443),
            remote_ip: "203.0.113.7".to_string(),
            remote_hostname: None,
            state: Some("Established".to_string()),
            ppid: None,
            command_line: None,
        }
    }

    #[test]
    fn valid_ipv4_with_null_optional_fields_is_accepted() {
        let r = ConnectionRecord {
            local_port: None,
            remote_hostname: None,
            state: None,
            ppid: None,
            command_line: None,
            ..base_record()
        };
        assert!(validate_record(&r).is_ok());
    }

    #[test]
    fn valid_ipv6_is_accepted() {
        let r = ConnectionRecord {
            local_addr: "2001:db8::5".to_string(),
            remote_addr: "[2001:db8::1]:443".to_string(),
            remote_ip: "2001:db8::1".to_string(),
            ..base_record()
        };
        assert!(validate_record(&r).is_ok());
    }

    #[test]
    fn udp_is_a_supported_protocol() {
        let r = ConnectionRecord {
            protocol: "udp".to_string(),
            ..base_record()
        };
        assert!(validate_record(&r).is_ok());
    }

    #[test]
    fn unparseable_remote_ip_is_rejected() {
        let r = ConnectionRecord {
            remote_ip: "999.1.2.3".to_string(),
            ..base_record()
        };
        assert!(validate_record(&r).unwrap_err().contains("remote_ip"));
    }

    #[test]
    fn hostname_in_remote_ip_field_is_rejected() {
        let r = ConnectionRecord {
            remote_ip: "evil.example.com".to_string(),
            ..base_record()
        };
        assert!(validate_record(&r).is_err());
    }

    #[test]
    fn zero_pid_is_rejected() {
        let r = ConnectionRecord {
            pid: 0,
            ..base_record()
        };
        assert!(validate_record(&r).unwrap_err().contains("pid"));
    }

    #[test]
    fn unknown_protocol_is_rejected() {
        let r = ConnectionRecord {
            protocol: "SCTP".to_string(),
            ..base_record()
        };
        assert!(validate_record(&r).unwrap_err().contains("protocol"));
    }

    #[test]
    fn zero_remote_port_is_rejected() {
        let r = ConnectionRecord {
            remote_addr: "203.0.113.7:0".to_string(),
            remote_port: Some(0),
            ..base_record()
        };
        assert!(validate_record(&r).unwrap_err().contains("remote_port"));
    }

    #[test]
    fn missing_remote_port_is_rejected() {
        let r = ConnectionRecord {
            remote_addr: "203.0.113.7:443".to_string(),
            remote_port: None,
            ..base_record()
        };
        assert!(validate_record(&r).is_err());
    }

    #[test]
    fn zero_local_port_is_rejected() {
        let r = ConnectionRecord {
            local_port: Some(0),
            ..base_record()
        };
        assert!(validate_record(&r).unwrap_err().contains("local_port"));
    }

    #[test]
    fn ipv4_ipv6_family_mismatch_is_rejected() {
        let r = ConnectionRecord {
            local_addr: "2001:db8::5".to_string(),
            ..base_record()
        };
        assert!(validate_record(&r)
            .unwrap_err()
            .contains("address family mismatch"));
    }

    #[test]
    fn remote_addr_ip_contradiction_is_rejected() {
        let r = ConnectionRecord {
            remote_addr: "203.0.113.99:443".to_string(),
            ..base_record()
        };
        assert!(validate_record(&r)
            .unwrap_err()
            .contains("contradicts remote_ip"));
    }

    #[test]
    fn remote_addr_port_contradiction_is_rejected() {
        let r = ConnectionRecord {
            remote_addr: "203.0.113.7:8443".to_string(),
            ..base_record()
        };
        assert!(validate_record(&r)
            .unwrap_err()
            .contains("contradicts remote_port"));
    }

    #[test]
    fn malformed_remote_addr_is_rejected() {
        let r = ConnectionRecord {
            remote_addr: "203.0.113.7".to_string(),
            ..base_record()
        };
        assert!(validate_record(&r).unwrap_err().contains("remote_addr"));
    }

    #[test]
    fn empty_hostname_string_is_rejected_but_null_is_allowed() {
        let mut r = base_record();
        r.remote_hostname = Some(String::new());
        assert!(validate_record(&r).unwrap_err().contains("remote_hostname"));

        r.remote_hostname = None;
        assert!(validate_record(&r).is_ok());
    }

    #[test]
    fn empty_process_name_is_rejected() {
        let r = ConnectionRecord {
            process_name: "   ".to_string(),
            ..base_record()
        };
        assert!(validate_record(&r).unwrap_err().contains("process_name"));
    }
}
