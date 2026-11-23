use std::collections::HashMap;
use std::net::IpAddr;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct CloudProvider {
    pub name: String,
    pub service: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudDetection {
    pub provider: CloudProvider,
    pub ip: IpAddr,
    pub domain: Option<String>,
    pub confidence: f32,
}

/// Result of an ARIN RDAP lookup for an IP that didn't match any known cloud provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArinResult {
    /// Short network handle, e.g. "MSFT", "AMAZON-2", "GOOGLE"
    pub handle: String,
    /// Full organization name from the registrant vCard
    pub org_name: String,
    /// CIDR range(s) the IP belongs to
    pub cidr: String,
    /// Two-letter country code, if present
    pub country: Option<String>,
}

/// Canonical identity for an IP address.
///
/// IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) are the same endpoint as
/// their plain IPv4 form, so they share one identity.
pub fn canonical_ip(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*ip),
        _ => *ip,
    }
}

/// The single key used for an address everywhere: ARIN queries, cache
/// entries, cache recovery and reports all key on this string, so one
/// address can never end up with two different identities.
pub fn arin_key(ip: &IpAddr) -> String {
    canonical_ip(ip).to_string()
}

/// Whether ARIN could possibly hold a record for this address.
///
/// Private, loopback, link-local and unspecified addresses are never
/// queried and never cached.  This one predicate is shared by
/// [`lookup_arin`], the parser and the server so all three agree on
/// which addresses are lookup candidates.
pub fn is_arin_candidate(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    if let IpAddr::V4(v4) = ip {
        if v4.is_private() || v4.is_link_local() {
            return false;
        }
    }
    true
}

/// Outcome of loading the persisted ARIN cache.
pub struct ArinCacheLoad {
    /// Cache entries keyed by [`arin_key`].  Empty when no cache file exists.
    pub entries: HashMap<String, Option<ArinResult>>,
    /// Number of entries salvaged from a corrupt cache file
    /// (0 when the file was clean or missing).
    pub recovered: usize,
    /// True when the file existed but did not parse as a whole cache.
    pub corrupt: bool,
}

/// Load the persisted ARIN cache, recovering whatever is salvageable.
///
/// A healthy cache — including caches written by older gibson versions —
/// parses directly.  A corrupt cache (e.g. truncated by a crash mid-write)
/// is salvaged entry-by-entry so a restart does not fall back to
/// re-querying every address as if the cache were empty.
pub fn load_arin_cache(path: &str) -> ArinCacheLoad {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            return ArinCacheLoad {
                entries: HashMap::new(),
                recovered: 0,
                corrupt: false,
            };
        }
    };

    // Fast path: well-formed cache (this is also the old on-disk format,
    // so caches and reports from previous runs keep working).
    if let Ok(map) = serde_json::from_str::<HashMap<String, Option<ArinResult>>>(&content) {
        return ArinCacheLoad {
            entries: normalize_cache_keys(map),
            recovered: 0,
            corrupt: false,
        };
    }

    // Recovery path: keep every entry that still parses.
    let entries = salvage_arin_cache(&content);
    ArinCacheLoad {
        recovered: entries.len(),
        corrupt: true,
        entries,
    }
}

/// Persist the ARIN cache atomically.
///
/// The cache is written to a sibling temp file and renamed over the target,
/// so a crash or kill mid-write can never leave half a cache behind.
pub fn persist_arin_cache(
    path: &str,
    cache: &HashMap<String, Option<ArinResult>>,
) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(cache).map_err(std::io::Error::other)?;
    let tmp_path = format!("{}.tmp", path);
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Re-key cache entries through [`arin_key`] so recovered entries share the
/// same address identity as fresh lookups.  On key collision a positive
/// result wins over a negative one.
fn normalize_cache_keys(
    map: HashMap<String, Option<ArinResult>>,
) -> HashMap<String, Option<ArinResult>> {
    let mut out: HashMap<String, Option<ArinResult>> = HashMap::with_capacity(map.len());
    for (key, value) in map {
        let key = match key.parse::<IpAddr>() {
            Ok(ip) => arin_key(&ip),
            Err(_) => key, // not an address literal — keep as-is
        };
        match out.entry(key) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(value);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                if e.get().is_none() && value.is_some() {
                    e.insert(value);
                }
            }
        }
    }
    out
}

/// Best-effort recovery of cache entries from a corrupt cache file.
fn salvage_arin_cache(content: &str) -> HashMap<String, Option<ArinResult>> {
    // Case 1: valid JSON with an unexpected shape — keep the entries that
    // still deserialize (e.g. a cache written by a different version).
    if let Ok(serde_json::Value::Object(obj)) = serde_json::from_str::<serde_json::Value>(content) {
        let salvaged: HashMap<String, Option<ArinResult>> = obj
            .into_iter()
            .filter_map(|(k, v)| {
                serde_json::from_value::<Option<ArinResult>>(v)
                    .ok()
                    .map(|r| (k, r))
            })
            .collect();
        return normalize_cache_keys(salvaged);
    }

    // Case 2: truncated or trailing-garbage JSON (e.g. half a cache left
    // behind by a crash).  Re-try successively shorter prefixes cut at entry
    // boundaries — the last complete entry may end in '}' *or* in a scalar
    // (`null`, a string), so both '}' and ',' are candidate cut points.
    let mut cuts: Vec<usize> = content
        .match_indices(|c| c == '}' || c == ',')
        .map(|(i, _)| i)
        .collect();
    cuts.sort_unstable_by(|a, b| b.cmp(a)); // longest prefix first
    cuts.dedup();
    for i in cuts.into_iter().take(128) {
        for candidate in [
            content[..=i].to_string(),                 // boundary char included
            format!("{}}}", content[..i].trim_end()),  // tail dropped, object closed
        ] {
            if let Ok(map) = serde_json::from_str::<HashMap<String, Option<ArinResult>>>(&candidate)
            {
                return normalize_cache_keys(map);
            }
        }
    }

    HashMap::new()
}

// Internal structs used only for deserialising the Microsoft Service Tags JSON.
#[derive(Deserialize)]
struct ServiceTagsRoot {
    values: Vec<ServiceTagEntry>,
}

#[derive(Deserialize)]
struct ServiceTagEntry {
    name: String,
    properties: ServiceTagProperties,
}

#[derive(Deserialize)]
struct ServiceTagProperties {
    region: String,
    #[serde(rename = "systemService")]
    system_service: String,
    #[serde(rename = "addressPrefixes")]
    address_prefixes: Vec<String>,
}

pub struct CloudDetector {
    ip_ranges: HashMap<String, Vec<IpNetwork>>,
    domain_patterns: HashMap<String, Vec<String>>,
    /// Ranges loaded from the Microsoft Service Tags feed.
    /// Each entry is (network, provider, service_tag_name).
    /// Sorted by prefix length descending so the most-specific range matches first.
    service_ranges: Vec<(IpNetwork, String, String)>,
}

impl CloudDetector {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for CloudDetector {
    fn default() -> Self {
        let mut detector = CloudDetector {
            ip_ranges: HashMap::new(),
            domain_patterns: HashMap::new(),
            service_ranges: Vec::new(),
        };
        detector.init_cloud_ranges();
        detector.init_domain_patterns();
        detector
    }
}

impl CloudDetector {
    /// Load Azure IP ranges from a Microsoft Service Tags JSON file.
    ///
    /// Download the file weekly from:
    ///   https://www.microsoft.com/en-us/download/details.aspx?id=56519
    ///
    /// Returns the number of CIDR entries loaded.  Regional entries (e.g.
    /// "AzureCloud.eastus") are skipped — the global entries cover the same
    /// IPs and give cleaner service names.
    pub fn load_service_tags(&mut self, path: &str) -> anyhow::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let root: ServiceTagsRoot = serde_json::from_str(&content)?;

        let before = self.service_ranges.len();

        for entry in root.values {
            // Skip regional entries — "AzureCloud.eastus" style names
            if !entry.properties.region.is_empty() {
                continue;
            }

            let service = if entry.properties.system_service.is_empty() {
                entry.name.clone()
            } else {
                entry.properties.system_service.clone()
            };

            for prefix_str in entry.properties.address_prefixes {
                if let Ok(network) = prefix_str.parse::<IpNetwork>() {
                    self.service_ranges.push((network, "Azure".to_string(), service.clone()));
                }
            }
        }

        // Most-specific range first: sort by prefix length descending.
        self.service_ranges.sort_by(|a, b| {
            let prefix_len = |n: &IpNetwork| match n {
                IpNetwork::V4(n) => n.prefix() as u32,
                IpNetwork::V6(n) => n.prefix() as u32,
            };
            prefix_len(&b.0).cmp(&prefix_len(&a.0))
        });

        Ok(self.service_ranges.len() - before)
    }

    fn init_cloud_ranges(&mut self) {
        // AWS — kept as fallback; see https://ip-ranges.amazonaws.com/ip-ranges.json
        self.ip_ranges.insert("AWS".to_string(), vec![
            "52.0.0.0/11".parse().unwrap(),
            "54.0.0.0/8".parse().unwrap(),
            "3.0.0.0/9".parse().unwrap(),
            "13.32.0.0/15".parse().unwrap(),
            "99.77.128.0/18".parse().unwrap(),
        ]);

        // Azure — kept as fallback when no Service Tags file is loaded.
        // Use --ip-ranges-file for accurate coverage.
        self.ip_ranges.insert("Azure".to_string(), vec![
            "40.0.0.0/7".parse().unwrap(),
            "20.0.0.0/6".parse().unwrap(),
            "13.64.0.0/11".parse().unwrap(),
            "52.96.0.0/12".parse().unwrap(),
        ]);

        // GCP — see https://www.gstatic.com/ipranges/cloud.json
        self.ip_ranges.insert("GCP".to_string(), vec![
            "35.184.0.0/13".parse().unwrap(),
            "34.0.0.0/8".parse().unwrap(),
            "104.154.0.0/15".parse().unwrap(),
            "146.148.0.0/17".parse().unwrap(),
        ]);

        self.ip_ranges.insert("Cloudflare".to_string(), vec![
            "173.245.48.0/20".parse().unwrap(),
            "103.21.244.0/22".parse().unwrap(),
            "103.22.200.0/22".parse().unwrap(),
            "103.31.4.0/22".parse().unwrap(),
            "141.101.64.0/18".parse().unwrap(),
            "104.16.0.0/12".parse().unwrap(),
            "172.64.0.0/13".parse().unwrap(),
            "131.0.72.0/22".parse().unwrap(),
        ]);

        self.ip_ranges.insert("DigitalOcean".to_string(), vec![
            "104.131.0.0/16".parse().unwrap(),
            "159.203.0.0/16".parse().unwrap(),
            "138.68.0.0/16".parse().unwrap(),
            "178.62.0.0/16".parse().unwrap(),
        ]);

        self.ip_ranges.insert("Akamai".to_string(), vec![
            "23.0.0.0/8".parse().unwrap(),
            "104.64.0.0/10".parse().unwrap(),
            "184.24.0.0/13".parse().unwrap(),
        ]);
    }

    fn init_domain_patterns(&mut self) {
        self.domain_patterns.insert("AWS".to_string(), vec![
            ".amazonaws.com".to_string(),
            ".aws.amazon.com".to_string(),
            ".cloudfront.net".to_string(),
            ".elasticbeanstalk.com".to_string(),
            ".elb.amazonaws.com".to_string(),
            ".s3.amazonaws.com".to_string(),
        ]);

        self.domain_patterns.insert("Azure".to_string(), vec![
            ".azure.com".to_string(),
            ".windows.net".to_string(),
            ".msecnd.net".to_string(),
            ".azureedge.net".to_string(),
            ".blob.core.windows.net".to_string(),
            ".cloudapp.azure.com".to_string(),
        ]);

        self.domain_patterns.insert("GCP".to_string(), vec![
            ".googleapis.com".to_string(),
            ".googleusercontent.com".to_string(),
            ".googlesyndication.com".to_string(),
            ".gstatic.com".to_string(),
            ".appspot.com".to_string(),
            ".firebaseapp.com".to_string(),
        ]);

        self.domain_patterns.insert("Cloudflare".to_string(), vec![
            ".cloudflare.com".to_string(),
            ".cloudflare-dns.com".to_string(),
            ".one.one.one.one".to_string(),
        ]);

        self.domain_patterns.insert("Akamai".to_string(), vec![
            ".akamai.net".to_string(),
            ".akamaihd.net".to_string(),
            ".akamaiedge.net".to_string(),
        ]);

        self.domain_patterns.insert("Fastly".to_string(), vec![
            ".fastly.net".to_string(),
            ".fastlylb.net".to_string(),
        ]);

        self.domain_patterns.insert("GitHub".to_string(), vec![
            ".github.com".to_string(),
            ".github.io".to_string(),
            ".githubusercontent.com".to_string(),
            ".githubassets.com".to_string(),
        ]);

        self.domain_patterns.insert("Microsoft".to_string(), vec![
            ".microsoft.com".to_string(),
            ".office.com".to_string(),
            ".office365.com".to_string(),
            ".live.com".to_string(),
            ".msftconnecttest.com".to_string(),
            ".windowsupdate.com".to_string(),
        ]);
    }

    pub fn detect_by_ip(&self, ip: &IpAddr) -> Option<CloudDetection> {
        // Service Tags take priority — more specific and accurate than the hardcoded ranges.
        for (network, provider, service) in &self.service_ranges {
            if network.contains(*ip) {
                return Some(CloudDetection {
                    provider: CloudProvider {
                        name: provider.clone(),
                        service: Some(service.clone()),
                        region: None,
                    },
                    ip: *ip,
                    domain: None,
                    confidence: 0.95,
                });
            }
        }

        // Fall back to hardcoded ranges.
        for (provider, ranges) in &self.ip_ranges {
            for range in ranges {
                if range.contains(*ip) {
                    return Some(CloudDetection {
                        provider: CloudProvider {
                            name: provider.clone(),
                            service: self.infer_service_from_ip(provider, ip),
                            region: None,
                        },
                        ip: *ip,
                        domain: None,
                        confidence: 0.9,
                    });
                }
            }
        }
        None
    }

    pub fn detect_by_domain(&self, domain: &str) -> Option<CloudDetection> {
        let domain_lower = domain.to_lowercase();

        for (provider, patterns) in &self.domain_patterns {
            for pattern in patterns {
                if domain_lower.ends_with(pattern) || domain_lower == pattern[1..] {
                    return Some(CloudDetection {
                        provider: CloudProvider {
                            name: provider.clone(),
                            service: self.infer_service_from_domain(provider, &domain_lower),
                            region: self.extract_region_from_domain(&domain_lower),
                        },
                        ip: "0.0.0.0".parse().unwrap(),
                        domain: Some(domain.to_string()),
                        confidence: 1.0,
                    });
                }
            }
        }
        None
    }

    pub fn detect(&self, ip: &IpAddr, domain: Option<&str>) -> Option<CloudDetection> {
        if let Some(domain) = domain {
            if let Some(mut detection) = self.detect_by_domain(domain) {
                detection.ip = *ip;
                return Some(detection);
            }
        }
        if let Some(mut detection) = self.detect_by_ip(ip) {
            detection.domain = domain.map(|d| d.to_string());
            return Some(detection);
        }
        None
    }

    fn infer_service_from_domain(&self, provider: &str, domain: &str) -> Option<String> {
        match provider {
            "AWS" => {
                if domain.contains("s3") { Some("S3".to_string()) }
                else if domain.contains("cloudfront") { Some("CloudFront".to_string()) }
                else if domain.contains("ec2") { Some("EC2".to_string()) }
                else if domain.contains("elb") { Some("ELB".to_string()) }
                else if domain.contains("rds") { Some("RDS".to_string()) }
                else if domain.contains("lambda") { Some("Lambda".to_string()) }
                else { None }
            }
            "Azure" => {
                if domain.contains("blob") { Some("Blob Storage".to_string()) }
                else if domain.contains("database") { Some("SQL Database".to_string()) }
                else if domain.contains("vault") { Some("Key Vault".to_string()) }
                else { None }
            }
            "GCP" => {
                if domain.contains("storage") { Some("Cloud Storage".to_string()) }
                else if domain.contains("appspot") { Some("App Engine".to_string()) }
                else if domain.contains("firebaseapp") { Some("Firebase".to_string()) }
                else { None }
            }
            _ => None,
        }
    }

    fn infer_service_from_ip(&self, provider: &str, _ip: &IpAddr) -> Option<String> {
        match provider {
            "Cloudflare" => Some("CDN".to_string()),
            "Akamai" => Some("CDN".to_string()),
            "Fastly" => Some("CDN".to_string()),
            _ => None,
        }
    }

    fn extract_region_from_domain(&self, domain: &str) -> Option<String> {
        let aws_regions = [
            ("us-east-1", "US East (N. Virginia)"),
            ("us-east-2", "US East (Ohio)"),
            ("us-west-1", "US West (N. California)"),
            ("us-west-2", "US West (Oregon)"),
            ("eu-west-1", "EU (Ireland)"),
            ("eu-central-1", "EU (Frankfurt)"),
            ("ap-southeast-1", "Asia Pacific (Singapore)"),
            ("ap-northeast-1", "Asia Pacific (Tokyo)"),
        ];
        for (code, name) in aws_regions {
            if domain.contains(code) {
                return Some(name.to_string());
            }
        }
        None
    }


    pub fn get_provider_summary(&self, detections: &[CloudDetection]) -> HashMap<String, ProviderSummary> {
        let mut summary: HashMap<String, ProviderSummary> = HashMap::new();

        for detection in detections {
            let entry = summary.entry(detection.provider.name.clone())
                .or_insert(ProviderSummary {
                    provider: detection.provider.name.clone(),
                    unique_ips: Vec::new(),
                    unique_domains: Vec::new(),
                    services: HashMap::new(),
                    total_connections: 0,
                });

            if !entry.unique_ips.contains(&detection.ip) {
                entry.unique_ips.push(detection.ip);
            }
            if let Some(domain) = &detection.domain {
                if !entry.unique_domains.contains(domain) {
                    entry.unique_domains.push(domain.clone());
                }
            }
            if let Some(service) = &detection.provider.service {
                *entry.services.entry(service.clone()).or_insert(0) += 1;
            }
            entry.total_connections += 1;
        }

        summary
    }
}

/// Query ARIN's RDAP bootstrap endpoint to identify who owns an IP address.
///
/// ARIN automatically routes to the correct RIR (RIPE, APNIC, LACNIC, AFRINIC)
/// for non-ARIN-managed IPs.  Private / loopback addresses are not queried.
pub async fn lookup_arin(ip: &IpAddr) -> anyhow::Result<Option<ArinResult>> {
    // Skip RFC 1918 and loopback — ARIN has no records for these.
    if !is_arin_candidate(ip) {
        return Ok(None);
    }

    let url = format!("https://rdap.arin.net/bootstrap/ip/{}", ip);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("gibson/0.2")
        .build()?;

    let resp = client
        .get(&url)
        .header("Accept", "application/rdap+json")
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let v: serde_json::Value = resp.json().await?;

    let handle = v["name"].as_str().unwrap_or("unknown").to_string();
    let org_name = extract_rdap_org_name(&v).unwrap_or_else(|| handle.clone());
    let country = v["country"].as_str().map(|s| s.to_string());

    // Build a human-readable CIDR string from cidr0_cidrs or start/end addresses.
    let cidr = if let Some(cidrs) = v["cidr0_cidrs"].as_array() {
        cidrs.iter()
            .filter_map(|c| {
                let prefix = c["v4prefix"].as_str().or_else(|| c["v6prefix"].as_str())?;
                let len = c["length"].as_u64()?;
                Some(format!("{}/{}", prefix, len))
            })
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        format!(
            "{} - {}",
            v["startAddress"].as_str().unwrap_or(""),
            v["endAddress"].as_str().unwrap_or("")
        )
    };

    Ok(Some(ArinResult { handle, org_name, cidr, country }))
}

/// Extract the registrant organisation name from an RDAP response.
/// Walks entities → registrant role → vCard fn field.
fn extract_rdap_org_name(v: &serde_json::Value) -> Option<String> {
    let entities = v["entities"].as_array()?;
    for entity in entities {
        // A malformed entity must not discard the registrant listed in a
        // later entity — skip it instead of abandoning the whole response.
        let roles = match entity["roles"].as_array() {
            Some(roles) => roles,
            None => continue,
        };
        let is_registrant = roles.iter().any(|r| r.as_str() == Some("registrant"));
        if !is_registrant {
            continue;
        }
        let fields = match entity["vcardArray"][1].as_array() {
            Some(fields) => fields,
            None => continue,
        };
        for field in fields {
            if field[0].as_str() == Some("fn") {
                if let Some(name) = field[3].as_str() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

#[derive(Debug, Serialize)]
pub struct ProviderSummary {
    pub provider: String,
    pub unique_ips: Vec<IpAddr>,
    pub unique_domains: Vec<String>,
    pub services: HashMap<String, usize>,
    pub total_connections: usize,
}

#[derive(Debug, Serialize)]
pub struct FirewallRule {
    pub direction: String,
    pub action: String,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub port: Option<u16>,
    pub provider: Option<String>,
    pub comment: String,
}

impl FirewallRule {
    pub fn to_iptables(&self) -> String {
        let mut cmd = format!(
            "iptables -A {} ",
            if self.direction == "OUTBOUND" { "OUTPUT" } else { "INPUT" }
        );
        cmd.push_str(&format!("-p {} ", self.protocol.to_lowercase()));
        if self.direction == "OUTBOUND" {
            cmd.push_str(&format!("-d {} ", self.destination));
        } else {
            cmd.push_str(&format!("-s {} ", self.source));
        }
        if let Some(port) = self.port {
            cmd.push_str(&format!("--dport {} ", port));
        }
        cmd.push_str(&format!("-j {} ", self.action));
        cmd.push_str(&format!("-m comment --comment \"{}\"", self.comment));
        cmd
    }

    pub fn to_windows_netsh(&self) -> String {
        format!(
            "netsh advfirewall firewall add rule name=\"{}\" dir={} action={} protocol={} remoteip={} {}",
            self.comment,
            if self.direction == "OUTBOUND" { "out" } else { "in" },
            self.action.to_lowercase(),
            self.protocol,
            if self.direction == "OUTBOUND" { &self.destination } else { &self.source },
            if let Some(port) = self.port {
                format!("remoteport={}", port)
            } else {
                String::new()
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sample_result() -> ArinResult {
        ArinResult {
            handle: "EXAMPLE-1".to_string(),
            org_name: "Example Org".to_string(),
            cidr: "203.0.113.0/24".to_string(),
            country: Some("US".to_string()),
        }
    }

    fn temp_cache_path(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!("gibson-arin-cache-{}-{}.json", tag, std::process::id()))
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn canonical_identity_unifies_mapped_v6() {
        let v4 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let mapped = IpAddr::V6("::ffff:8.8.8.8".parse::<Ipv6Addr>().unwrap());
        assert_eq!(canonical_ip(&mapped), v4);
        assert_eq!(arin_key(&mapped), arin_key(&v4));
        assert_eq!(arin_key(&v4), "8.8.8.8");
    }

    #[test]
    fn arin_candidate_predicate_matches_lookup_rules() {
        assert!(!is_arin_candidate(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_arin_candidate(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_arin_candidate(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_arin_candidate(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_arin_candidate(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_arin_candidate(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn cache_round_trip_preserves_negative_entries() {
        let path = temp_cache_path("roundtrip");

        let mut cache = HashMap::new();
        cache.insert("203.0.113.1".to_string(), Some(sample_result()));
        cache.insert("198.51.100.1".to_string(), None); // negative entry
        persist_arin_cache(&path, &cache).unwrap();

        let load = load_arin_cache(&path);
        assert!(!load.corrupt);
        assert_eq!(load.recovered, 0);
        assert_eq!(load.entries.len(), 2);
        assert!(load.entries["198.51.100.1"].is_none());
        assert_eq!(
            load.entries["203.0.113.1"].as_ref().unwrap().org_name,
            "Example Org"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_cache_is_salvaged_not_discarded() {
        let path = temp_cache_path("corrupt");

        // Half a cache, as left behind by a crash mid-write: two complete
        // entries (one positive, one negative) plus a truncated third.
        let half = "{\n  \"203.0.113.1\": {\n    \"handle\": \"EXAMPLE-1\",\n    \"org_name\": \"Example Org\",\n    \"cidr\": \"203.0.113.0/24\",\n    \"country\": \"US\"\n  },\n  \"198.51.100.1\": null,\n  \"192.0.2.1\": {\n    \"handle\": \"TR";
        std::fs::write(&path, half).unwrap();

        let load = load_arin_cache(&path);
        assert!(load.corrupt);
        assert_eq!(load.recovered, 2);
        assert_eq!(
            load.entries["203.0.113.1"].as_ref().unwrap().org_name,
            "Example Org"
        );
        assert!(load.entries["198.51.100.1"].is_none());
        assert!(!load.entries.contains_key("192.0.2.1")); // truncated entry dropped

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn old_cache_entries_without_country_still_load() {
        let path = temp_cache_path("oldformat");
        let json = r#"{"203.0.113.1": {"handle": "EXAMPLE-1", "org_name": "Example Org", "cidr": "203.0.113.0/24"}}"#;
        std::fs::write(&path, json).unwrap();

        let load = load_arin_cache(&path);
        assert!(!load.corrupt);
        let entry = load.entries["203.0.113.1"].as_ref().unwrap();
        assert_eq!(entry.org_name, "Example Org");
        assert_eq!(entry.country, None);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn org_name_survives_malformed_entities() {
        // The first entity has no roles array — it must be skipped, not
        // abort the walk and orphan the registrant in the second entity.
        let v = serde_json::json!({
            "entities": [
                { "handle": "ABUSE-1" },
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Example Org"]
                    ]]
                }
            ]
        });
        assert_eq!(extract_rdap_org_name(&v), Some("Example Org".to_string()));
    }
}
