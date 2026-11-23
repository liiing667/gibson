use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::asn_db::AsnDb;
use crate::cloud_detector::{lookup_arin, ArinResult, CloudDetector};
use crate::collector_v2::{ConnectionRecord, UploadBatch};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(about = "Receive and analyze data from multiple collectors")]
pub struct ServerOpts {
    /// Address to listen on
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub bind: String,

    /// Required API key (sent by collectors as X-API-Key header)
    #[arg(long)]
    pub api_key: Option<String>,

    /// Microsoft Service Tags JSON for accurate Azure detection
    #[arg(long)]
    pub ip_ranges_file: Option<String>,

    /// JSON file for persisting ARIN lookup results across restarts.
    /// IPs already in the file are never re-queried.
    #[arg(long)]
    pub arin_cache: Option<String>,

    /// Local ip2asn TSV database from iptoasn.com for instant offline lookups.
    /// When provided, ARIN is never queried.
    ///
    /// Download:
    ///   curl -O https://iptoasn.com/data/ip2asn-v4.tsv.gz && gunzip ip2asn-v4.tsv.gz
    #[arg(long)]
    pub asn_db: Option<String>,
}

// ─── session storage ──────────────────────────────────────────────────────────

struct Session {
    id: String,
    hostname: String,
    first_seen_unix: u64,
    last_seen_unix: u64,
    records: Vec<ConnectionRecord>,
    /// Identity of every sample that has been admitted to this session.
    ///
    /// Uploads are retried by the agents and collectors routinely backfill old
    /// batches.  Without this set those retries look like fresh observations
    /// and change every downstream count (and, for the beacon detector, the
    /// grouping of one connection's samples).
    admitted: HashMap<SampleKey, usize>,
}

impl Session {
    fn new(hostname: String, records: Vec<ConnectionRecord>) -> Self {
        let now = unix_now();
        let mut session = Session {
            id: format!("{}-{}", hostname, now),
            hostname,
            first_seen_unix: now,
            last_seen_unix: now,
            records: Vec::new(),
            admitted: HashMap::new(),
        };
        session.admit(records);
        session
    }

    /// Admit a batch of samples and return the number of *new* observations.
    ///
    /// Admission is the only place where the session's observation set grows.
    /// It is deliberately idempotent: replaying the same batch (a retry, a
    /// duplicate upload, or a late backfill of records we already have) adds
    /// nothing and therefore cannot change the candidate report for the
    /// current observation generation.
    fn admit(&mut self, incoming: Vec<ConnectionRecord>) -> usize {
        let mut accepted = 0usize;
        for record in incoming {
            let key = SampleKey::from(&record);
            let existing_index = self.admitted.get(&key).copied();
            if let Some(index) = existing_index {
                // A retry may be re-stamped inside the same observation
                // window.  Keep a deterministic representative (earliest
                // timestamp, lexicographically smallest hostname) so replay
                // order cannot change interval evidence.
                let existing = &mut self.records[index];
                let mut host = existing.remote_hostname.clone();
                merge_hostname(&mut host, record.remote_hostname.as_deref());
                if record.timestamp < existing.timestamp {
                    *existing = record;
                }
                existing.remote_hostname = host;
            } else {
                let index = self.records.len();
                self.records.push(record);
                self.admitted.insert(key, index);
                accepted += 1;
            }
        }
        accepted
    }

    /// Number of distinct observations in the current generation.
    ///
    /// This is content-derived rather than wall-clock derived: replaying the
    /// same observations (in any order or batch split) yields the same value.
    fn observation_generation(&self) -> u64 {
        self.records.len() as u64
    }
}

/// Stable identity of one collected sample.
///
/// The (normalized) timestamp is part of the identity, but non-semantic
/// presentation fields (reverse-DNS name, command line, parent PID)
/// intentionally are not: a retried upload may resolve DNS again or refresh
/// those fields while still describing exactly the same socket observation.
/// Timestamps are normalized to `observation_bucket` here as well, so a retry
/// that is re-stamped by a second within the same poll still deduplicates.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SampleKey {
    timestamp_bucket: i64,
    pid: u32,
    process_name: String,
    protocol: String,
    local_addr: String,
    local_port: Option<u16>,
    remote_addr: String,
    remote_port: Option<u16>,
    remote_ip: String,
    state: Option<String>,
}

impl From<&ConnectionRecord> for SampleKey {
    fn from(record: &ConnectionRecord) -> Self {
        SampleKey {
            timestamp_bucket: observation_bucket(system_time_secs(record.timestamp))
                .unwrap_or(i64::MIN),
            pid: record.pid,
            process_name: record.process_name.clone(),
            protocol: record.protocol.clone(),
            local_addr: record.local_addr.clone(),
            local_port: record.local_port,
            remote_addr: record.remote_addr.clone(),
            remote_port: record.remote_port,
            remote_ip: record.remote_ip.clone(),
            state: record.state.clone(),
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    // Keyed by hostname so batches from the same machine accumulate.
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    cloud_detector: Arc<CloudDetector>,
    api_key: Option<String>,
    // IP string -> ARIN result (None = looked up, no record found).
    // Persisted to --arin-cache file so cold restarts don't re-query known IPs.
    arin_cache: Arc<Mutex<HashMap<String, Option<ArinResult>>>>,
    arin_cache_path: Option<String>,
    // When present, used instead of ARIN for all unknown IP lookups.
    asn_db: Option<Arc<AsnDb>>,
}

// ─── API types ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    machines: usize,
    total_records: usize,
}

#[derive(Serialize)]
struct UploadResponse {
    session_id: String,
    records_received: usize,
    records_accepted: usize,
    records_duplicate: usize,
    total_for_machine: usize,
    /// Content-derived generation of the observation set used by analysis.
    observation_generation: u64,
}

#[derive(Serialize)]
pub struct SessionSummary {
    id: String,
    hostname: String,
    first_seen_unix: u64,
    last_seen_unix: u64,
    record_count: usize,
    /// Number of distinct observations in this generation.
    observation_generation: u64,
}

// ─── pattern report types ─────────────────────────────────────────────────────

/// Full analysis for one machine.
#[derive(Serialize)]
pub struct SessionAnalysis {
    pub session: SessionSummary,
    pub patterns: PatternReport,
    /// Generation covered by `patterns`.  Admission and analysis are always
    /// performed against this same immutable generation.
    pub observation_generation: u64,
    /// ARIN registration info for IPs not matched by any known cloud provider.
    pub arin_results: HashMap<String, ArinResult>,
}

#[derive(Serialize)]
pub struct PatternReport {
    /// Processes/IPs with suspiciously regular inter-connection timing.
    pub beaconing_candidates: Vec<BeaconingCandidate>,
    /// Hostnames whose left-most label has high Shannon entropy (possible DGA).
    pub high_entropy_hosts: Vec<HighEntropyHost>,
    /// Connections to non-standard destination ports.
    pub port_anomalies: Vec<PortAnomaly>,
    /// Processes with many connections to IPs not matched by any known cloud provider.
    pub high_freq_noncloud: Vec<HighFreqTalker>,
}

#[derive(Serialize)]
pub struct BeaconingCandidate {
    pub process: String,
    pub remote_ip: String,
    pub remote_host: Option<String>,
    /// Number of distinct appearances after normalizing timestamps onto the
    /// absolute observation grid and deduplicating repeated polls.
    pub distinct_appearances: usize,
    /// Mean time between re-establishments (seconds).
    pub interval_mean_secs: f64,
    pub interval_stddev_secs: f64,
    /// Coefficient of variation (stddev/mean). Low = regular = suspicious.
    pub jitter_ratio: f64,
    pub is_known_cloud: bool,
    /// 0–10.  ≥ 5 warrants investigation.
    pub suspicion_score: f64,
}

#[derive(Serialize)]
pub struct HighEntropyHost {
    pub hostname: String,
    pub process: String,
    /// Shannon entropy of the leftmost DNS label (bits per character).
    pub entropy_bits_per_char: f64,
    pub connection_count: usize,
}

#[derive(Serialize)]
pub struct PortAnomaly {
    pub port: u16,
    pub process: String,
    pub remote_ip: String,
    pub remote_host: Option<String>,
    pub connection_count: usize,
}

#[derive(Serialize)]
pub struct HighFreqTalker {
    pub process: String,
    pub remote_ip: String,
    pub remote_host: Option<String>,
    pub connection_count: usize,
}

/// Cross-machine analysis combining all sessions.
#[derive(Serialize)]
pub struct CrossMachineReport {
    /// IPs observed on more than one machine — could indicate shared C2 or CDN.
    pub shared_ips: Vec<SharedIp>,
    /// Per-machine pattern summaries.
    pub by_machine: Vec<MachineSummary>,
    /// ARIN info for every unmatched IP seen across all machines.
    pub arin_results: HashMap<String, ArinResult>,
}

#[derive(Serialize)]
pub struct SharedIp {
    pub remote_ip: String,
    pub remote_host: Option<String>,
    pub seen_on: Vec<String>,
    pub total_connections: usize,
    pub is_known_cloud: bool,
}

#[derive(Serialize)]
pub struct MachineSummary {
    pub hostname: String,
    pub record_count: usize,
    pub observation_generation: u64,
    pub beacon_count: usize,
    pub high_entropy_count: usize,
    pub noncloud_freq_count: usize,
}

// ─── server entry point ───────────────────────────────────────────────────────

pub async fn run_server(opts: ServerOpts) -> anyhow::Result<()> {
    let mut cloud_detector = CloudDetector::new();
    if let Some(path) = &opts.ip_ranges_file {
        match cloud_detector.load_service_tags(path) {
            Ok(n) => println!("✓ Loaded {} CIDR ranges from {}", n, path),
            Err(e) => eprintln!("Warning: failed to load IP ranges: {}", e),
        }
    }

    // Load persisted ARIN cache from disk if available.
    let arin_cache_initial: HashMap<String, Option<ArinResult>> =
        if let Some(path) = &opts.arin_cache {
            match std::fs::read_to_string(path) {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };
    if !arin_cache_initial.is_empty() {
        println!(
            "✓ Loaded {} cached ARIN entries from {:?}",
            arin_cache_initial.len(),
            opts.arin_cache
        );
    }

    let asn_db = if let Some(path) = &opts.asn_db {
        match AsnDb::load(path) {
            Ok(db) => {
                println!("✓ Loaded {} ASN ranges from {} (offline lookups enabled)", db.len(), path);
                Some(Arc::new(db))
            }
            Err(e) => {
                eprintln!("Warning: failed to load ASN DB '{}': {}", path, e);
                None
            }
        }
    } else {
        None
    };

    let state = AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        cloud_detector: Arc::new(cloud_detector),
        api_key: opts.api_key.clone(),
        arin_cache: Arc::new(Mutex::new(arin_cache_initial)),
        arin_cache_path: opts.arin_cache.clone(),
        asn_db,
    };

    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/upload", post(handle_upload))
        .route("/api/sessions", get(handle_list_sessions))
        .route("/api/sessions/:hostname", get(handle_get_session))
        .route("/api/patterns", get(handle_cross_machine))
        .with_state(state);

    let addr: std::net::SocketAddr = opts
        .bind
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid bind address '{}': {}", opts.bind, e))?;

    println!("Analysis server listening on http://{}", addr);
    println!("  POST /upload          — receive data from collectors");
    println!("  GET  /api/sessions    — list machines");
    println!("  GET  /api/sessions/:h — patterns for one machine");
    println!("  GET  /api/patterns    — cross-machine analysis");
    if opts.api_key.is_some() {
        println!("✓ API key authentication enabled");
    } else {
        println!("⚠  No API key — all uploads accepted");
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ─── handlers ─────────────────────────────────────────────────────────────────

async fn handle_health(State(state): State<AppState>) -> Json<HealthResponse> {
    let sessions = state.sessions.lock().unwrap();
    let total_records: usize = sessions.values().map(|s| s.records.len()).sum();
    Json(HealthResponse {
        status: "ok",
        machines: sessions.len(),
        total_records,
    })
}

/// Returns `Err(UNAUTHORIZED)` if the state has an API key and the request
/// does not present a matching `X-API-Key` header.  When no key is configured
/// every request is allowed through.
fn check_api_key(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    if let Some(expected) = &state.api_key {
        let provided = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if provided != expected {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(())
}

async fn handle_upload(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<UploadResponse>, StatusCode> {
    // Upload is intentionally unauthenticated — agents are anonymous.
    let batch: UploadBatch =
        serde_json::from_str(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let hostname = batch.hostname.clone();
    let received_count = batch.records.len();
    let session_id;
    let total_for_machine;
    let accepted_count;
    let observation_generation;

    {
        let mut sessions = state.sessions.lock().unwrap();
        let session = sessions
            .entry(hostname.clone())
            .or_insert_with(|| Session::new(hostname.clone(), Vec::new()));

        // Admission and generation bookkeeping happen under the same lock as
        // the analysis snapshot.  A batch is therefore either completely in a
        // generation or completely absent from it — never half-admitted.
        accepted_count = session.admit(batch.records);
        // A late/old report must not move the session's wall-clock watermark
        // backwards if the server clock is adjusted.
        session.last_seen_unix = session.last_seen_unix.max(unix_now());
        session_id = session.id.clone();
        total_for_machine = session.records.len();
        observation_generation = session.observation_generation();
    }

    println!(
        "[upload] {} — {} received, {} new ({} total, generation {})",
        hostname, received_count, accepted_count, total_for_machine, observation_generation
    );

    Ok(Json(UploadResponse {
        session_id,
        records_received: received_count,
        records_accepted: accepted_count,
        records_duplicate: received_count.saturating_sub(accepted_count),
        total_for_machine,
        observation_generation,
    }))
}

async fn handle_list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionSummary>>, StatusCode> {
    check_api_key(&state, &headers)?;
    let sessions = state.sessions.lock().unwrap();
    let mut list: Vec<SessionSummary> = sessions
        .values()
        .map(|s| SessionSummary {
            id: s.id.clone(),
            hostname: s.hostname.clone(),
            first_seen_unix: s.first_seen_unix,
            last_seen_unix: s.last_seen_unix,
            record_count: s.records.len(),
            observation_generation: s.observation_generation(),
        })
        .collect();
    list.sort_by(|a, b| {
        a.first_seen_unix
            .cmp(&b.first_seen_unix)
            .then_with(|| a.hostname.cmp(&b.hostname))
    });
    Ok(Json(list))
}

async fn handle_get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hostname): Path<String>,
) -> Result<Json<SessionAnalysis>, StatusCode> {
    check_api_key(&state, &headers)?;
    // Hold the session lock only long enough to clone what we need,
    // then release it before doing any async work.
    let (summary, patterns, unmatched, observation_generation) = {
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.get(&hostname).ok_or(StatusCode::NOT_FOUND)?;

        // Take one immutable snapshot of the admitted records and derive every
        // part of the report from it.  Admission, timestamp normalization and
        // candidate reporting therefore describe the same observation
        // generation even if a late upload is being handled concurrently.
        let records = session.records.clone();
        let observation_generation = session.observation_generation();
        let patterns = analyze_patterns(&records, &state.cloud_detector);
        let unmatched = collect_unmatched_ips(&records, &state.cloud_detector);
        let summary = SessionSummary {
            id: session.id.clone(),
            hostname: session.hostname.clone(),
            first_seen_unix: session.first_seen_unix,
            last_seen_unix: session.last_seen_unix,
            record_count: records.len(),
            observation_generation,
        };
        (summary, patterns, unmatched, observation_generation)
    };

    let arin_results = resolve_ip_ownership(
        &unmatched,
        state.asn_db.as_deref(),
        &state.arin_cache,
        state.arin_cache_path.as_deref(),
    )
    .await;

    Ok(Json(SessionAnalysis {
        session: summary,
        patterns,
        observation_generation,
        arin_results,
    }))
}

async fn handle_cross_machine(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CrossMachineReport>, StatusCode> {
    check_api_key(&state, &headers)?;
    // Collect everything we need while holding the lock, then drop it.
    let (shared_ips, by_machine, all_unmatched) = {
        let sessions = state.sessions.lock().unwrap();

        let mut ip_to_machines: HashMap<String, HashSet<String>> = HashMap::new();
        let mut ip_to_host: HashMap<String, Option<String>> = HashMap::new();
        let mut ip_conn_count: HashMap<String, usize> = HashMap::new();

        for session in sessions.values() {
            for r in &session.records {
                ip_to_machines
                    .entry(r.remote_ip.clone())
                    .or_default()
                    .insert(session.hostname.clone());
                ip_to_host
                    .entry(r.remote_ip.clone())
                    .or_insert_with(|| r.remote_hostname.clone());
                *ip_conn_count.entry(r.remote_ip.clone()).or_insert(0) += 1;
            }
        }

        let mut shared_ips: Vec<SharedIp> = ip_to_machines
            .into_iter()
            .filter(|(_, machines)| machines.len() > 1)
            .map(|(ip, machines)| {
                let parsed: Option<IpAddr> = ip.parse().ok();
                let is_known_cloud = parsed
                    .and_then(|a| {
                        let host = ip_to_host.get(&ip).and_then(|h| h.as_deref());
                        state.cloud_detector.detect(&a, host)
                    })
                    .is_some();
                SharedIp {
                    remote_host: ip_to_host.get(&ip).and_then(|h| h.clone()),
                    seen_on: machines.into_iter().collect(),
                    total_connections: *ip_conn_count.get(&ip).unwrap_or(&0),
                    is_known_cloud,
                    remote_ip: ip,
                }
            })
            .collect();

        shared_ips.sort_by(|a, b| {
            b.is_known_cloud
                .cmp(&a.is_known_cloud)
                .reverse()
                .then(b.total_connections.cmp(&a.total_connections))
                .then_with(|| a.remote_ip.cmp(&b.remote_ip))
        });

        let mut by_machine: Vec<MachineSummary> = sessions
            .values()
            .map(|s| {
                let p = analyze_patterns(&s.records, &state.cloud_detector);
                MachineSummary {
                    hostname: s.hostname.clone(),
                    record_count: s.records.len(),
                    observation_generation: s.observation_generation(),
                    beacon_count: p.beaconing_candidates.len(),
                    high_entropy_count: p.high_entropy_hosts.len(),
                    noncloud_freq_count: p.high_freq_noncloud.len(),
                }
            })
            .collect();
        by_machine.sort_by(|a, b| a.hostname.cmp(&b.hostname));

        // Aggregate unmatched IPs across all sessions.
        let all_unmatched: Vec<IpAddr> = sessions
            .values()
            .flat_map(|s| collect_unmatched_ips(&s.records, &state.cloud_detector))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        (shared_ips, by_machine, all_unmatched)
    };

    let arin_results = resolve_ip_ownership(
        &all_unmatched,
        state.asn_db.as_deref(),
        &state.arin_cache,
        state.arin_cache_path.as_deref(),
    )
    .await;

    Ok(Json(CrossMachineReport {
        shared_ips,
        by_machine,
        arin_results,
    }))
}

// ─── ARIN helpers ─────────────────────────────────────────────────────────────

/// Return every public IP in `records` that the cloud detector does not recognise.
fn collect_unmatched_ips(records: &[ConnectionRecord], detector: &CloudDetector) -> Vec<IpAddr> {
    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut matched: HashSet<IpAddr> = HashSet::new();

    for r in records {
        let ip: IpAddr = match r.remote_ip.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        if let IpAddr::V4(v4) = ip {
            if v4.is_private() || v4.is_link_local() {
                continue;
            }
        }
        seen.insert(ip);
        if detector.detect(&ip, r.remote_hostname.as_deref()).is_some() {
            matched.insert(ip);
        }
    }

    seen.difference(&matched).copied().collect()
}

/// Resolve ownership for a slice of IPs.
///
/// Priority:
///   1. Local ASN DB (instant, offline) — when `--asn-db` is provided.
///   2. In-memory + file-backed ARIN cache — for IPs not yet seen.
///   3. Live ARIN RDAP query — only for cache misses when no local DB is present.
async fn resolve_ip_ownership(
    ips: &[IpAddr],
    asn_db: Option<&AsnDb>,
    cache: &Arc<Mutex<HashMap<String, Option<ArinResult>>>>,
    cache_path: Option<&str>,
) -> HashMap<String, ArinResult> {
    if let Some(db) = asn_db {
        // Local DB path: instant O(log n) lookup, zero network calls.
        return ips
            .iter()
            .filter_map(|ip| {
                db.lookup(ip).map(|r| {
                    (
                        ip.to_string(),
                        ArinResult {
                            handle: format!("AS{}", r.asn),
                            org_name: r.org_name.clone(),
                            cidr: String::new(),
                            country: r.country.clone(),
                        },
                    )
                })
            })
            .collect();
    }

    // ARIN path: check cache first, query only misses.
    let to_lookup: Vec<IpAddr> = {
        let guard = cache.lock().unwrap();
        ips.iter()
            .filter(|ip| !guard.contains_key(&ip.to_string()))
            .copied()
            .collect()
    };

    if !to_lookup.is_empty() {
        println!("ARIN: querying {} uncached IPs...", to_lookup.len());

        let mut set = tokio::task::JoinSet::new();
        for ip in to_lookup {
            set.spawn(async move { (ip, lookup_arin(&ip).await) });
        }

        let mut updates: Vec<(String, Option<ArinResult>)> = Vec::new();
        while let Some(result) = set.join_next().await {
            if let Ok((ip, Ok(arin))) = result {
                updates.push((ip.to_string(), arin));
            }
        }

        println!("ARIN: {} responses received", updates.len());

        let mut guard = cache.lock().unwrap();
        for (ip_str, arin) in updates {
            guard.insert(ip_str, arin);
        }

        if let Some(path) = cache_path {
            let json = serde_json::to_string_pretty(&*guard).unwrap_or_default();
            if let Err(e) = std::fs::write(path, json) {
                eprintln!("Warning: failed to persist ARIN cache to {}: {}", path, e);
            }
        }
    }

    let guard = cache.lock().unwrap();
    ips.iter()
        .filter_map(|ip| {
            guard
                .get(&ip.to_string())
                .and_then(|r| r.as_ref())
                .map(|r| (ip.to_string(), r.clone()))
        })
        .collect()
}

// ─── pattern analysis ─────────────────────────────────────────────────────────

pub fn analyze_patterns(records: &[ConnectionRecord], detector: &CloudDetector) -> PatternReport {
    PatternReport {
        beaconing_candidates: detect_beaconing(records, detector),
        high_entropy_hosts: detect_high_entropy_hosts(records),
        port_anomalies: detect_port_anomalies(records),
        high_freq_noncloud: detect_high_freq_noncloud(records, detector),
    }
}

/// Width of one normalized observation bucket, in seconds.
///
/// This is the collector's default poll cadence: all samples from one poll
/// belong to the same observation.  Buckets are aligned to the Unix epoch, not
/// to the first record in the batch, which is what makes late arrivals and
/// clock regressions stable.
pub const OBSERVATION_WINDOW_SECS: f64 = 5.0;

/// Gaps at or below this threshold are treated as repeated observations of the
/// same connection rather than a new connection attempt.
const MIN_BEACON_INTERVAL_SECS: f64 = 15.0;

/// Consecutive samples this close together are repeated observations of the
/// same poll burst.  This is deliberately larger than the historical 6-second
/// window so collectors polling every 10 seconds are handled too, while still
/// staying below the minimum beacon interval.
const POLL_ADJACENT_SECS: f64 = 10.0;

/// Convert a `SystemTime` into signed seconds since the Unix epoch.
///
/// `SystemTime::duration_since` fails for instants before the epoch.  Treating
/// those as zero would merge every such sample into one bucket and would make
/// a clock regression look like a burst.  Keep the sign instead so ordering is
/// still well defined.
fn system_time_secs(ts: SystemTime) -> f64 {
    match ts.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs_f64(),
        Err(err) => -err.duration().as_secs_f64(),
    }
}

/// Map an instant to its absolute, epoch-aligned observation bucket.
fn observation_bucket(secs: f64) -> Option<i64> {
    if !secs.is_finite() {
        return None;
    }
    let bucket = (secs / OBSERVATION_WINDOW_SECS).round();
    if bucket < i64::MIN as f64 || bucket > i64::MAX as f64 {
        return None;
    }
    Some(bucket as i64)
}

/// Keep the lexicographically smallest non-empty hostname so duplicate
/// observations with different DNS outcomes still produce deterministic output.
fn merge_hostname(current: &mut Option<String>, candidate: Option<&str>) {
    let candidate = match candidate {
        Some(name) if !name.is_empty() => name,
        _ => return,
    };
    let should_replace = match current.as_deref() {
        Some(existing) => existing > candidate,
        None => true,
    };
    if should_replace {
        *current = Some(candidate.to_string());
    }
}

/// One normalized appearance inside an absolute observation bucket.
///
/// The bucket decides *membership* (and therefore cannot be moved by a late
/// arrival), while the representative keeps the earliest timestamp observed in
/// that bucket so interval evidence stays in real units.
struct ObservationSlot {
    observed_at: f64,
}

/// Detect processes that re-connect to the same IP at suspiciously regular intervals.
///
/// Algorithm:
///   1. Group records by (process, remote_ip).
///   2. Normalize every timestamp onto a fixed, epoch-aligned observation
///      grid.  Samples that describe the same poll therefore collapse to one
///      observation regardless of when they arrive, whether they were retried,
///      or how the batch was split.  The grid is absolute (it does not depend
///      on the smallest timestamp seen so far), so a late/backfilled sample
///      cannot move the bucket boundaries of observations already in the
///      generation.
///   3. Walk the normalized observations in time order, collapse poll-adjacent
///      re-samples into one appearance, and compute inter-arrival gaps.  Only
///      gaps > 15 s are kept — smaller gaps are just consecutive polls.
///   4. If there are ≥ 3 such gaps, compute mean, stddev, and CV (stddev/mean).
///      CV < 0.4 → regular timing → beacon candidate.
///
/// The function is a pure function of the *set* of admitted observations.  It
/// never relies on insertion order, so replaying the same sequence in a
/// different order (or with duplicated/backfilled batches) produces the same
/// candidates and interval evidence.
pub fn detect_beaconing(
    records: &[ConnectionRecord],
    detector: &CloudDetector,
) -> Vec<BeaconingCandidate> {
    // (process, remote_ip) -> (observation bucket -> representative, first seen hostname)
    let mut groups: HashMap<
        (String, String),
        (BTreeMap<i64, ObservationSlot>, Option<String>),
    > = HashMap::new();

    for r in records {
        let secs = system_time_secs(r.timestamp);
        let bucket = match observation_bucket(secs) {
            Some(bucket) => bucket,
            None => continue,
        };
        let key = (r.process_name.clone(), r.remote_ip.clone());
        let entry = groups
            .entry(key)
            .or_insert_with(|| (BTreeMap::new(), None));

        // Keep the earliest instant in the bucket as its representative and
        // choose the hostname deterministically.  A retry may have resolved
        // DNS differently; picking the lexicographically smallest name makes
        // the report independent of upload order.
        {
            let slot = entry
                .0
                .entry(bucket)
                .or_insert_with(|| ObservationSlot {
                    observed_at: secs,
                });
            if secs < slot.observed_at {
                slot.observed_at = secs;
            }
        }
        merge_hostname(&mut entry.1, r.remote_hostname.as_deref());
    }

    let mut candidates = Vec::new();

    for ((process, ip), (buckets, remote_host)) in groups {
        // BTreeMap already yields the buckets in normalized-time order, so the
        // result depends only on the observation set, not on arrival order.
        // Within that order, collapse retries/re-samples that land in
        // neighbouring buckets but still belong to the same polling burst.
        let mut distinct: Vec<f64> = Vec::new();
        let mut previous_sample: Option<f64> = None;
        for slot in buckets.values() {
            let observed_at = slot.observed_at;
            let starts_new_burst = previous_sample
                .map_or(true, |previous| observed_at - previous > POLL_ADJACENT_SECS);
            if starts_new_burst {
                distinct.push(observed_at);
            }
            previous_sample = Some(observed_at);
        }

        if distinct.len() < 5 {
            continue;
        }

        // Inter-arrival gaps — only the ones large enough to indicate a deliberate
        // re-connection rather than just consecutive polls.
        let gaps: Vec<f64> = distinct
            .windows(2)
            .map(|w| w[1] - w[0])
            .filter(|&g| g > MIN_BEACON_INTERVAL_SECS)
            .collect();

        if gaps.len() < 3 {
            continue;
        }

        let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
        let variance =
            gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
        let stddev = variance.sqrt();
        let jitter_ratio = if mean > 0.0 { stddev / mean } else { 1.0 };

        if jitter_ratio > 0.4 {
            continue;
        }

        let ip_addr: IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let is_known_cloud = detector.detect(&ip_addr, remote_host.as_deref()).is_some();

        // Suspicion score 0–10:
        //   Base = how regular the timing is (1 = perfectly regular, 0 = barely qualifies)
        //   Cloud factor = known CDN/provider reduces score (still worth showing)
        //   Count factor = more gaps = more confident
        let base = 1.0 - (jitter_ratio / 0.4);
        let cloud_factor = if is_known_cloud { 0.35 } else { 1.0 };
        let count_factor = ((gaps.len() as f64 - 3.0) / 7.0).clamp(0.0, 1.0);
        let suspicion_score =
            ((base * cloud_factor * (0.5 + 0.5 * count_factor)) * 10.0).round() / 10.0;

        candidates.push(BeaconingCandidate {
            process,
            remote_ip: ip,
            remote_host,
            distinct_appearances: distinct.len(),
            interval_mean_secs: (mean * 10.0).round() / 10.0,
            interval_stddev_secs: (stddev * 10.0).round() / 10.0,
            jitter_ratio: (jitter_ratio * 1000.0).round() / 1000.0,
            is_known_cloud,
            suspicion_score,
        });
    }

    // Deterministic total ordering: equal-scoring groups must not reorder
    // across replays because of HashMap iteration order.
    candidates.sort_by(|a, b| {
        b.suspicion_score
            .partial_cmp(&a.suspicion_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.process.cmp(&b.process))
            .then_with(|| a.remote_ip.cmp(&b.remote_ip))
            .then_with(|| b.distinct_appearances.cmp(&a.distinct_appearances))
    });
    candidates.truncate(20);
    candidates
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    freq.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

// Known-clean domain suffixes — we skip entropy checks for these.
const CLEAN_SUFFIXES: &[&str] = &[
    ".microsoft.com",
    ".windows.com",
    ".windowsupdate.com",
    ".msftconnecttest.com",
    ".azure.com",
    ".windows.net",
    ".office.com",
    ".live.com",
    ".amazonaws.com",
    ".cloudfront.net",
    ".akamaiedge.net",
    ".akamaihd.net",
    ".cloudflare.com",
    ".github.com",
    ".githubusercontent.com",
    ".google.com",
    ".googleapis.com",
    ".gstatic.com",
];

/// Flag hostnames whose leftmost DNS label has high Shannon entropy.
/// High entropy labels suggest algorithmically-generated names (DGA).
fn detect_high_entropy_hosts(records: &[ConnectionRecord]) -> Vec<HighEntropyHost> {
    // hostname -> (process, count)
    let mut seen: HashMap<String, (String, usize)> = HashMap::new();

    for r in records {
        let hostname = match &r.remote_hostname {
            Some(h) if h.len() > 8 && h.contains('.') => h.clone(),
            _ => continue,
        };
        if hostname.parse::<IpAddr>().is_ok() {
            continue; // bare IP, not a hostname
        }
        if CLEAN_SUFFIXES.iter().any(|s| hostname.ends_with(s)) {
            continue;
        }
        let entry = seen
            .entry(hostname)
            .or_insert((r.process_name.clone(), 0));
        entry.1 += 1;
    }

    let mut findings: Vec<HighEntropyHost> = seen
        .into_iter()
        .filter_map(|(hostname, (process, count))| {
            let label = hostname.split('.').next().unwrap_or(&hostname);
            if label.len() < 8 {
                return None;
            }
            let entropy = shannon_entropy(label);
            if entropy < 3.5 {
                return None;
            }
            Some(HighEntropyHost {
                hostname,
                process,
                entropy_bits_per_char: (entropy * 100.0).round() / 100.0,
                connection_count: count,
            })
        })
        .collect();

    findings.sort_by(|a, b| {
        b.entropy_bits_per_char
            .partial_cmp(&a.entropy_bits_per_char)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.hostname.cmp(&b.hostname))
            .then_with(|| a.process.cmp(&b.process))
    });
    findings.truncate(20);
    findings
}

const STANDARD_PORTS: &[u16] = &[
    80, 443, 8080, 8443, 8888, 53, 25, 587, 465, 993, 995, 143, 21, 22, 23, 3389, 5985,
    5986,
];

/// Flag connections to destination ports outside the well-known set.
fn detect_port_anomalies(records: &[ConnectionRecord]) -> Vec<PortAnomaly> {
    // (port, process, remote_ip) -> (count, remote_host)
    let mut groups: HashMap<(u16, String, String), (usize, Option<String>)> =
        HashMap::new();

    for r in records {
        let port = match r.remote_port {
            Some(p) if !STANDARD_PORTS.contains(&p) && p > 0 => p,
            _ => continue,
        };
        let key = (port, r.process_name.clone(), r.remote_ip.clone());
        let entry = groups
            .entry(key)
            .or_insert((0, r.remote_hostname.clone()));
        entry.0 += 1;
    }

    let mut findings: Vec<PortAnomaly> = groups
        .into_iter()
        .map(|((port, process, ip), (count, host))| PortAnomaly {
            port,
            process,
            remote_ip: ip,
            remote_host: host,
            connection_count: count,
        })
        .collect();

    findings.sort_by(|a, b| {
        b.connection_count
            .cmp(&a.connection_count)
            .then_with(|| a.port.cmp(&b.port))
            .then_with(|| a.process.cmp(&b.process))
            .then_with(|| a.remote_ip.cmp(&b.remote_ip))
    });
    findings.truncate(25);
    findings
}

/// Flag processes with many connections to IPs not matched by any cloud provider.
/// Legitimate software almost always talks to known infrastructure;
/// unknown high-count destinations warrant a closer look.
fn detect_high_freq_noncloud(
    records: &[ConnectionRecord],
    detector: &CloudDetector,
) -> Vec<HighFreqTalker> {
    // (process, remote_ip) -> (count, remote_host)
    let mut groups: HashMap<(String, String), (usize, Option<String>)> = HashMap::new();

    for r in records {
        let ip: IpAddr = match r.remote_ip.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        if detector.detect(&ip, r.remote_hostname.as_deref()).is_some() {
            continue; // known cloud provider — expected
        }
        if ip.is_private() {
            continue; // skip RFC 1918 / internal
        }
        let key = (r.process_name.clone(), r.remote_ip.clone());
        let entry = groups
            .entry(key)
            .or_insert((0, r.remote_hostname.clone()));
        entry.0 += 1;
    }

    let mut findings: Vec<HighFreqTalker> = groups
        .into_iter()
        .filter(|(_, (count, _))| *count >= 5)
        .map(|((process, ip), (count, host))| HighFreqTalker {
            process,
            remote_ip: ip,
            remote_host: host,
            connection_count: count,
        })
        .collect();

    findings.sort_by(|a, b| {
        b.connection_count
            .cmp(&a.connection_count)
            .then_with(|| a.process.cmp(&b.process))
            .then_with(|| a.remote_ip.cmp(&b.remote_ip))
    });
    findings.truncate(25);
    findings
}

// ─── IpAddr::is_private helper (stable in 1.75+) ─────────────────────────────

trait IsPrivate {
    fn is_private(&self) -> bool;
}

impl IsPrivate for IpAddr {
    fn is_private(&self) -> bool {
        match self {
            IpAddr::V4(a) => a.is_private() || a.is_link_local(),
            IpAddr::V6(a) => a.is_loopback(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: i64) -> SystemTime {
        if secs >= 0 {
            std::time::UNIX_EPOCH + Duration::from_secs(secs as u64)
        } else {
            std::time::UNIX_EPOCH - Duration::from_secs((-secs) as u64)
        }
    }

    fn record(secs: i64, local_port: u16) -> ConnectionRecord {
        ConnectionRecord {
            timestamp: at(secs),
            pid: 4242,
            process_name: "beacon.exe".to_string(),
            protocol: "TCP".to_string(),
            local_addr: "10.0.0.5".to_string(),
            local_port: Some(local_port),
            remote_addr: "203.0.113.9:443".to_string(),
            remote_port: Some(443),
            remote_ip: "203.0.113.9".to_string(),
            remote_hostname: Some("c2.example".to_string()),
            state: Some("Established".to_string()),
            ppid: Some(1),
            command_line: None,
        }
    }

    fn summary(candidates: &[BeaconingCandidate]) -> Vec<(String, String, usize, u64, u64)> {
        let mut out: Vec<_> = candidates
            .iter()
            .map(|c| {
                (
                    c.process.clone(),
                    c.remote_ip.clone(),
                    c.distinct_appearances,
                    (c.interval_mean_secs * 1000.0).round() as u64,
                    (c.interval_stddev_secs * 1000.0).round() as u64,
                )
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn beacon_evidence_is_order_and_duplicate_invariant() {
        let detector = CloudDetector::new();
        let ordered: Vec<_> = [0_i64, 60, 120, 180, 240, 300]
            .iter()
            .map(|&t| record(t, 50000))
            .collect();

        let mut replayed = Vec::new();
        for &t in [300_i64, 0, 180, 60, 240, 120].iter() {
            replayed.push(record(t, 50000));
            replayed.push(record(t, 50000)); // duplicate upload of the same sample
        }

        let a = detect_beaconing(&ordered, &detector);
        let b = detect_beaconing(&replayed, &detector);

        assert_eq!(summary(&a), summary(&b));
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].distinct_appearances, 6);
        assert_eq!(a[0].interval_mean_secs, 60.0);
        assert_eq!(a[0].interval_stddev_secs, 0.0);
    }

    #[test]
    fn repeated_polls_of_one_connection_are_not_a_beacon() {
        let detector = CloudDetector::new();
        let polls: Vec<_> = (0_i64..=300)
            .step_by(5)
            .map(|t| record(t, 50000))
            .collect();
        assert!(detect_beaconing(&polls, &detector).is_empty());

        let slower_polls: Vec<_> = (0_i64..=300)
            .step_by(10)
            .map(|t| record(t, 50000))
            .collect();
        assert!(detect_beaconing(&slower_polls, &detector).is_empty());
    }

    #[test]
    fn repeated_samples_inside_a_beacon_burst_do_not_add_intervals() {
        let detector = CloudDetector::new();
        let mut records = Vec::new();
        for &t in [0_i64, 60, 120, 180, 240, 300].iter() {
            records.push(record(t, 50000));
            records.push(record(t + 5, 50000));
        }

        let candidates = detect_beaconing(&records, &detector);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].distinct_appearances, 6);
        assert_eq!(candidates[0].interval_mean_secs, 60.0);
        assert_eq!(candidates[0].interval_stddev_secs, 0.0);
    }

    #[test]
    fn late_backfill_does_not_shift_existing_observations() {
        let detector = CloudDetector::new();
        let mut records: Vec<_> = [0_i64, 60, 120, 180, 240, 300]
            .iter()
            .map(|&t| record(t, 50000))
            .collect();
        let before = summary(&detect_beaconing(&records, &detector));

        // A retry/backfill carrying an older copy of an observation that we
        // already have must be ignored by admission and by the detector.
        records.insert(0, record(60, 50000));
        let after = summary(&detect_beaconing(&records, &detector));

        assert_eq!(before, after);
    }

    #[test]
    fn duplicate_samples_are_not_admitted_twice() {
        let first = record(0, 50000);
        let second = record(60, 50000);
        let mut session = Session::new("host-a".to_string(), vec![first.clone(), second.clone()]);

        assert_eq!(session.records.len(), 2);
        let generation = session.observation_generation();
        assert_eq!(session.admit(vec![first, second]), 0);
        assert_eq!(session.observation_generation(), generation);

        // A genuinely new, older observation is accepted but does not move the
        // session's generation backwards.
        assert_eq!(session.admit(vec![record(-60, 50000)]), 1);
        assert_eq!(session.observation_generation(), generation + 1);
    }

    #[test]
    fn admission_is_independent_of_replay_order() {
        // Both records fall in the same normalized observation bucket.
        let earlier = record(3, 50000);
        let later = record(4, 50000);

        let mut a = Session::new("host-a".to_string(), vec![later.clone()]);
        let mut b = Session::new("host-a".to_string(), vec![earlier.clone()]);
        assert_eq!(a.admit(vec![earlier]), 0);
        assert_eq!(b.admit(vec![later]), 0);

        assert_eq!(a.records.len(), 1);
        assert_eq!(b.records.len(), 1);
        assert_eq!(a.records[0].timestamp, b.records[0].timestamp);
        assert_eq!(a.observation_generation(), b.observation_generation());
    }
}
