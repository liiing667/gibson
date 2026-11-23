//! Contract tests for the upload-time semantic gate.
//!
//! These exercise `gibson::validation` through the public crate API so the
//! rules stay pinned even if the internal record layout changes.

use gibson::collector_v2::ConnectionRecord;
use gibson::validation::{validate_connection_fields, validate_record};
use std::time::{Duration, SystemTime};

fn record() -> ConnectionRecord {
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
fn ipv4_ipv6_and_null_optionals_are_preserved() {
    assert!(validate_record(&record()).is_ok());

    let nulls = ConnectionRecord {
        local_port: None,
        remote_hostname: None,
        state: None,
        ppid: None,
        command_line: None,
        ..record()
    };
    assert!(validate_record(&nulls).is_ok());

    let v6 = ConnectionRecord {
        local_addr: "2001:db8::5".to_string(),
        remote_addr: "[2001:db8::1]:443".to_string(),
        remote_ip: "2001:db8::1".to_string(),
        ..record()
    };
    assert!(validate_record(&v6).is_ok());
}

#[test]
fn contradictions_are_rejected_before_they_reach_a_session() {
    let cases: Vec<ConnectionRecord> = vec![
        // Garbage / hostname in IP field
        ConnectionRecord {
            remote_ip: "999.1.2.3".to_string(),
            ..record()
        },
        ConnectionRecord {
            remote_ip: "evil.example.com".to_string(),
            ..record()
        },
        // Zero / missing ports and pid
        ConnectionRecord {
            remote_port: Some(0),
            remote_addr: "203.0.113.7:0".to_string(),
            ..record()
        },
        ConnectionRecord {
            remote_port: None,
            ..record()
        },
        ConnectionRecord {
            local_port: Some(0),
            ..record()
        },
        ConnectionRecord { pid: 0, ..record() },
        // Unknown protocol
        ConnectionRecord {
            protocol: "SCTP".to_string(),
            ..record()
        },
        // IPv4/IPv6 family mismatch
        ConnectionRecord {
            local_addr: "2001:db8::5".to_string(),
            ..record()
        },
        // remote_addr contradicts split fields
        ConnectionRecord {
            remote_addr: "203.0.113.99:443".to_string(),
            ..record()
        },
        ConnectionRecord {
            remote_addr: "203.0.113.7:8443".to_string(),
            ..record()
        },
        // Empty optional string instead of null
        ConnectionRecord {
            remote_hostname: Some(String::new()),
            ..record()
        },
        // Empty process name
        ConnectionRecord {
            process_name: String::new(),
            ..record()
        },
    ];

    assert!(!cases.is_empty());
    for bad in &cases {
        assert!(
            validate_record(bad).is_err(),
            "expected rejection of {bad:?}"
        );
    }
}

#[test]
fn shared_common_field_gate_matches_the_full_gate() {
    let good = record();
    assert!(validate_connection_fields(
        good.pid,
        &good.process_name,
        &good.protocol,
        &good.remote_ip,
        good.remote_port,
        good.remote_hostname.as_deref(),
    )
    .is_ok());

    // The subset gate cannot see address-family/endpoint contradictions,
    // but must still reject every common-field contradiction.
    assert!(validate_connection_fields(
        0,
        "nc.exe",
        "TCP",
        "203.0.113.7",
        Some(443),
        None,
    )
    .is_err());
    assert!(validate_connection_fields(
        1,
        "nc.exe",
        "ICMP",
        "203.0.113.7",
        Some(443),
        None,
    )
    .is_err());
    assert!(validate_connection_fields(
        1,
        "nc.exe",
        "TCP",
        "not-an-ip",
        Some(443),
        None,
    )
    .is_err());
    assert!(validate_connection_fields(
        1,
        "nc.exe",
        "TCP",
        "203.0.113.7",
        Some(0),
        None,
    )
    .is_err());
}
