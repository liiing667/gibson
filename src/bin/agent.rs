//! Gibson lightweight agent — deploy and run with zero flags.
//!
//! ## Build
//!
//! All config is set at compile time via environment variables and burned
//! into the binary. No flags, no config files needed on the target machine.
//!
//! ```bash
//! AGENT_SERVER="http://10.0.1.5:8080/upload" \
//! AGENT_KEY="labkey123" \
//! AGENT_INTERVAL="5" \
//! AGENT_BATCH="200" \
//! AGENT_DURATION="0" \
//! AGENT_DNS="false" \
//! AGENT_ENCRYPT_KEY="mysecretpassword" \
//! cargo build --release --bin agent
//! ```
//!
//! Then drop the binary on the target and run it — no arguments needed.
//!
//! ## Environment variables
//!
//! | Variable          | Default                          | Description                                      |
//! |-------------------|----------------------------------|--------------------------------------------------|
//! | AGENT_SERVER      | http://localhost:8080/upload     | Upload endpoint URL                              |
//! | AGENT_KEY         | (none)                           | X-API-Key header value                           |
//! | AGENT_INTERVAL    | 5                                | Socket poll interval in seconds                  |
//! | AGENT_BATCH       | 200                              | Records per upload batch                         |
//! | AGENT_DURATION    | 0                                | Run duration seconds (0 = run forever)           |
//! | AGENT_DNS         | false                            | Resolve IPs to hostnames (true/false)            |
//! | AGENT_ESTABLISHED | true                             | ESTABLISHED connections only (true/false)        |
//! | AGENT_LOCAL_COPY  | false                            | Keep local .jsonl copy (true/false)              |
//! | AGENT_COMPRESS    | false                            | Gzip compress before upload (true/false)         |
//! | AGENT_ENCRYPT_KEY | (none)                           | AES-256 encrypt payload (password or 64-hex key) |
//! | AGENT_UA          | (none, sends reqwest/x.y)        | HTTP User-Agent header (for proxy bypass)         |

use gibson::collector_v2::{CollectorOpts, SecureCollector};

// ── All config baked in at compile time via option_env!() ────────────────────
// String/optional values use const; numeric/bool values are parsed at startup
// (still embedded in the binary — option_env! is a compile-time macro).

const SERVER_URL: &str = match option_env!("AGENT_SERVER") {
    Some(s) => s,
    None => "http://localhost:8080/upload",
};

const API_KEY: Option<&str> = option_env!("AGENT_KEY");
const ENCRYPT_KEY: Option<&str> = option_env!("AGENT_ENCRYPT_KEY");
const USER_AGENT: Option<&str> = option_env!("AGENT_UA");

// Numeric / bool config — parsed once at startup from compile-time strings.
fn cfg_interval()    -> u64  { parse_u64(option_env!("AGENT_INTERVAL"),    5)     }
fn cfg_batch()       -> usize { parse_u64(option_env!("AGENT_BATCH"),     200) as usize }
fn cfg_duration()    -> u64  { parse_u64(option_env!("AGENT_DURATION"),     0)     } // 0 = forever
fn cfg_dns()         -> bool { parse_bool(option_env!("AGENT_DNS"),        false)  }
fn cfg_established() -> bool { parse_bool(option_env!("AGENT_ESTABLISHED"), true)  }
fn cfg_local_copy()  -> bool { parse_bool(option_env!("AGENT_LOCAL_COPY"), false)  }
fn cfg_compress()    -> bool { parse_bool(option_env!("AGENT_COMPRESS"),   false)  }

fn parse_u64(s: Option<&str>, default: u64) -> u64 {
    s.and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn parse_bool(s: Option<&str>, default: bool) -> bool {
    match s {
        Some("true") | Some("1") | Some("yes") => true,
        Some("false") | Some("0") | Some("no") => false,
        _ => default,
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let duration = cfg_duration();
    let run_secs = if duration == 0 { u64::MAX } else { duration };

    println!("Gibson agent");
    println!("  server:     {}", SERVER_URL);
    println!("  user-agent: {}", USER_AGENT.unwrap_or("(default reqwest)"));
    println!("  interval: {}s  batch: {}  established-only: {}  dns: {}",
        cfg_interval(), cfg_batch(), cfg_established(), cfg_dns());
    println!("  duration: {}  local-copy: {}  compress: {}  encrypted: {}",
        if run_secs == u64::MAX { "forever".to_string() } else { format!("{}s", run_secs) },
        cfg_local_copy(), cfg_compress(), ENCRYPT_KEY.is_some());

    let opts = CollectorOpts {
        upload_url:          Some(SERVER_URL.to_string()),
        api_key:             API_KEY.map(str::to_string),
        encrypt_key:         ENCRYPT_KEY.map(str::to_string),
        duration_seconds:    run_secs,
        interval_seconds:    cfg_interval(),
        batch_size:          cfg_batch(),
        established_only:    cfg_established(),
        enable_dns:          cfg_dns(),
        compress:            cfg_compress(),
        delete_after_upload: !cfg_local_copy(),
        user_agent:          USER_AGENT.map(str::to_string),
        output:              "agent_connections.jsonl".to_string(),
        verbose:             false,
    };

    let mut collector = SecureCollector::new(opts)?;
    collector.run().await
}
