use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use dns_lookup::lookup_addr;
use flate2::write::GzEncoder;
use flate2::Compression;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, SocketInfo};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use sysinfo::{Pid, PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};
use tokio::{task, time::sleep};

#[derive(Parser, Debug)]
#[command(author, version, about = "Secure network connection collector")]
pub struct CollectorOpts {
    /// How long to run in seconds
    #[arg(long, default_value_t = 300)]
    pub duration_seconds: u64,

    /// Poll interval seconds
    #[arg(long, default_value_t = 5)]
    pub interval_seconds: u64,

    /// Output file (JSONL format)
    #[arg(long, default_value = "connections.jsonl")]
    pub output: String,

    /// Perform DNS lookups
    #[arg(long)]
    pub enable_dns: bool,

    /// Live output to console
    #[arg(long)]
    pub verbose: bool,

    /// Enable gzip compression
    #[arg(long)]
    pub compress: bool,

    /// Encryption key (64-char hex for raw AES-256 key, or any string for password-derived key)
    #[arg(long)]
    pub encrypt_key: Option<String>,

    /// Upload URL (POST endpoint)
    #[arg(long)]
    pub upload_url: Option<String>,

    /// Upload API key (sent as X-API-Key header)
    #[arg(long)]
    pub api_key: Option<String>,

    /// Delete local file after successful upload
    #[arg(long)]
    pub delete_after_upload: bool,

    /// Records per upload batch
    #[arg(long, default_value_t = 100)]
    pub batch_size: usize,

    /// Only record ESTABLISHED TCP connections (filters TIME_WAIT, CLOSE_WAIT, etc.)
    #[arg(long)]
    pub established_only: bool,

    /// HTTP User-Agent header sent with uploads (useful for proxies)
    #[arg(long)]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub timestamp: SystemTime,
    pub pid: u32,
    pub process_name: String,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: Option<u16>,
    pub remote_addr: String,
    pub remote_port: Option<u16>,
    pub remote_ip: String,
    pub remote_hostname: Option<String>,
    pub state: Option<String>,
    pub ppid: Option<u32>,
    pub command_line: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionMetadata {
    pub start_time: SystemTime,
    pub end_time: SystemTime,
    pub hostname: String,
    /// OS family: "windows", "linux", "macos"
    pub platform: String,
    /// Full OS version string, e.g. "Windows 10 Pro 22H2" or "Ubuntu 22.04"
    pub os_version: Option<String>,
    /// Kernel / build version, e.g. "10.0.19045" (Windows) or "5.15.0-76-generic"
    pub kernel_version: Option<String>,
    /// CPU architecture, e.g. "x86_64" or "aarch64"
    pub arch: String,
    /// Current username — helps identify which account ran the agent
    pub username: Option<String>,
    /// Primary outbound local IP (the interface used for internet-bound traffic)
    pub local_ip: Option<String>,
    pub total_records: usize,
    pub unique_pids: usize,
    pub unique_remote_ips: usize,
    pub encrypted: bool,
    pub compressed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadBatch {
    pub hostname: String,
    pub batch_id: String,
    pub timestamp: SystemTime,
    pub records: Vec<ConnectionRecord>,
    pub metadata: Option<CollectionMetadata>,
}

pub struct SecureCollector {
    opts: CollectorOpts,
    // Incremental metadata tracking — avoids accumulating all records in memory.
    unique_pids: HashSet<u32>,
    unique_ips: HashSet<String>,
    total_records: usize,
    resolved_names: Arc<Mutex<HashMap<IpAddr, String>>>,
    sys: System,
    encryption_key: Option<Vec<u8>>,
    // Present when the key was derived from a password (must be stored with ciphertext
    // so the same key can be re-derived on decryption).
    encryption_salt: Option<[u8; 16]>,
    upload_client: Option<reqwest::Client>,
}

impl SecureCollector {
    pub fn new(opts: CollectorOpts) -> anyhow::Result<Self> {
        let refresh = RefreshKind::new().with_processes(ProcessRefreshKind::everything());
        let mut sys = System::new_with_specifics(refresh);
        sys.refresh_all();

        let (encryption_key, encryption_salt) = match &opts.encrypt_key {
            Some(key) => {
                let (k, s) = Self::parse_encryption_key(key)?;
                (Some(k), s)
            }
            None => (None, None),
        };

        let upload_client = if opts.upload_url.is_some() {
            let mut builder = reqwest::Client::builder();
            if let Some(ua) = &opts.user_agent {
                builder = builder.user_agent(ua.clone());
            }
            Some(builder.build()?)
        } else {
            None
        };

        Ok(SecureCollector {
            opts,
            unique_pids: HashSet::new(),
            unique_ips: HashSet::new(),
            total_records: 0,
            resolved_names: Arc::new(Mutex::new(HashMap::new())),
            sys,
            encryption_key,
            encryption_salt,
            upload_client,
        })
    }

    /// Parse or derive a 32-byte AES-256 key.
    ///
    /// A 64-char hex string is treated as a raw key (no KDF).
    /// Any other string is treated as a password and stretched with
    /// PBKDF2-HMAC-SHA256 (100 000 iterations, random 16-byte salt).
    /// The salt is returned alongside the key so it can be prepended to
    /// the ciphertext for later decryption.
    fn parse_encryption_key(key: &str) -> anyhow::Result<(Vec<u8>, Option<[u8; 16]>)> {
        if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes: anyhow::Result<Vec<u8>> = (0..32)
                .map(|i| {
                    u8::from_str_radix(&key[i * 2..i * 2 + 2], 16)
                        .map_err(|e| anyhow::anyhow!("Invalid hex key: {}", e))
                })
                .collect();
            Ok((bytes?, None))
        } else {
            let mut salt = [0u8; 16];
            rand::thread_rng().fill(&mut salt);
            let mut key_bytes = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(key.as_bytes(), &salt, 100_000, &mut key_bytes);
            Ok((key_bytes.to_vec(), Some(salt)))
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let start = Instant::now();
        let start_time = SystemTime::now();
        let duration = Duration::from_secs(self.opts.duration_seconds);
        let poll_interval = Duration::from_secs(self.opts.interval_seconds);

        println!(
            "Starting secure collection for {} seconds...",
            self.opts.duration_seconds
        );
        if self.opts.compress {
            println!("✓ Compression enabled");
        }
        if self.encryption_key.is_some() {
            println!("✓ Encryption enabled");
        }
        if let Some(url) = &self.opts.upload_url {
            println!("✓ Upload to {} enabled", url);
        }

        // Stream records to a temp file as they arrive — data survives a crash mid-run.
        let temp_path = format!("{}.tmp", self.opts.output);
        let file = std::fs::File::create(&temp_path)?;
        let mut writer = BufWriter::new(file);

        let mut batch_buffer: Vec<ConnectionRecord> = Vec::new();
        let mut batch_count: usize = 0;

        while start.elapsed() < duration {
            let now = SystemTime::now();
            self.sys.refresh_processes();

            let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
            let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;

            match get_sockets_info(af, proto) {
                Ok(sockets) => {
                    let mut records_this_poll: usize = 0;

                    for si in sockets {
                        if let Some(record) = self.process_socket(si, now).await {
                            // Track metadata without keeping all records in memory.
                            self.unique_pids.insert(record.pid);
                            self.unique_ips.insert(record.remote_ip.clone());
                            self.total_records += 1;
                            records_this_poll += 1;

                            // Persist immediately so a crash loses at most one poll's data.
                            let json_line = serde_json::to_string(&record)?;
                            writeln!(writer, "{}", json_line)?;

                            batch_buffer.push(record);
                        }
                    }

                    // Upload batch when threshold is reached.
                    if batch_buffer.len() >= self.opts.batch_size && self.opts.upload_url.is_some() {
                        batch_count += 1;
                        if let Err(e) =
                            self.upload_records(&batch_buffer, batch_count, now, None).await
                        {
                            eprintln!("Failed to upload batch {}: {:?}", batch_count, e);
                        } else if self.opts.verbose {
                            println!(
                                "✓ Uploaded batch {} ({} records)",
                                batch_count,
                                batch_buffer.len()
                            );
                        }
                        batch_buffer.clear();
                    }

                    if self.opts.verbose && records_this_poll > 0 {
                        println!(
                            "Collected {} connections at {}",
                            records_this_poll,
                            humantime::format_rfc3339(now)
                        );
                    }
                }
                Err(e) => eprintln!("Failed to query sockets: {:?}", e),
            }

            let remaining = duration.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }
            sleep(poll_interval.min(remaining)).await;
        }

        writer.flush()?;
        drop(writer);

        // Upload remaining records with final metadata.
        if !batch_buffer.is_empty() && self.opts.upload_url.is_some() {
            batch_count += 1;
            let metadata = self.generate_metadata(start_time)?;
            if let Err(e) = self
                .upload_records(
                    &batch_buffer,
                    batch_count,
                    SystemTime::now(),
                    Some(metadata),
                )
                .await
            {
                eprintln!("Failed to upload final batch: {:?}", e);
            }
        }

        let save_locally = self.opts.upload_url.is_none() || !self.opts.delete_after_upload;
        if save_locally {
            self.finalize_output(&temp_path)?;
        } else {
            std::fs::remove_file(&temp_path)?;
        }

        let metadata = self.generate_metadata(start_time)?;
        println!("\nCollection complete!");
        println!("Total records:     {}", metadata.total_records);
        println!("Unique PIDs:       {}", metadata.unique_pids);
        println!("Unique remote IPs: {}", metadata.unique_remote_ips);

        Ok(())
    }

    async fn process_socket(&self, si: SocketInfo, now: SystemTime) -> Option<ConnectionRecord> {
        let pid = si.associated_pids.first().copied()?;

        // netstat2 0.9's UdpSocketInfo only has local_addr/local_port — no remote endpoint.
        // Only TCP entries carry a remote address, so skip UDP here.
        let tcp = match si.protocol_socket_info {
            netstat2::ProtocolSocketInfo::Tcp(tcp) => tcp,
            netstat2::ProtocolSocketInfo::Udp(_) => return None,
        };

        if self.opts.established_only && tcp.state != netstat2::TcpState::Established {
            return None;
        }

        let remote_ip: IpAddr = tcp.remote_addr;
        let remote_port = tcp.remote_port;
        let local_ip: IpAddr = tcp.local_addr;
        let local_port = tcp.local_port;
        let state = Some(format!("{:?}", tcp.state));

        if remote_ip.is_loopback() || remote_ip.is_unspecified() {
            return None;
        }

        let proc = self.sys.process(Pid::from(pid as usize));
        let process_name = proc
            .map(|p: &sysinfo::Process| p.name().to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        let ppid = proc.and_then(|p| p.parent()).map(|id| id.as_u32());
        let command_line = proc
            .map(|p| p.cmd().join(" "))
            .filter(|s| !s.is_empty());

        let remote_hostname = if self.opts.enable_dns {
            self.resolve_hostname(&remote_ip).await
        } else {
            None
        };

        Some(ConnectionRecord {
            timestamp: now,
            pid,
            process_name,
            protocol: "TCP".to_string(),
            local_addr: local_ip.to_string(),
            local_port: Some(local_port),
            remote_addr: format!("{}:{}", remote_ip, remote_port),
            remote_port: Some(remote_port),
            remote_ip: remote_ip.to_string(),
            remote_hostname,
            state,
            ppid,
            command_line,
        })
    }

    async fn resolve_hostname(&self, ip: &IpAddr) -> Option<String> {
        let resolved = self.resolved_names.clone();
        let ip_clone = *ip;

        task::spawn_blocking(move || {
            let mut cache = resolved.lock().unwrap();
            if let Some(name) = cache.get(&ip_clone) {
                return Some(name.clone());
            }
            match lookup_addr(&ip_clone) {
                Ok(name) => {
                    cache.insert(ip_clone, name.clone());
                    Some(name)
                }
                Err(_) => None,
            }
        })
        .await
        .ok()
        .flatten()
    }

    /// Compress (if enabled), then encrypt (if enabled), then write to the final path.
    ///
    /// Compression before encryption is intentional: ciphertext is pseudorandom and
    /// incompressible, so compressing after encryption wastes CPU and saves nothing.
    fn finalize_output(&self, temp_path: &str) -> anyhow::Result<()> {
        let plaintext = std::fs::read(temp_path)?;

        // Checksum covers plaintext so it is useful for verifying the raw data.
        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        let checksum = format!("{:x}", hasher.finalize());

        let data = if self.opts.compress {
            self.compress_data(&plaintext)?
        } else {
            plaintext
        };

        let (data, suffix) = if self.encryption_key.is_some() {
            let encrypted = self.encrypt_data(&data)?;
            let ext = if self.opts.compress { ".gz.enc" } else { ".enc" };
            (encrypted, ext)
        } else if self.opts.compress {
            (data, ".gz")
        } else {
            (data, "")
        };

        let final_path = if suffix.is_empty() {
            self.opts.output.clone()
        } else {
            format!("{}{}", self.opts.output, suffix)
        };

        std::fs::write(&final_path, &data)?;
        std::fs::remove_file(temp_path)?;
        println!("✓ Written to {} (checksum: {})", final_path, &checksum[..8]);

        Ok(())
    }

    fn compress_data(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    /// Encrypt data with AES-256-GCM.
    ///
    /// Wire format (binary): `[salt? (16 B)] [nonce (12 B)] [ciphertext]`
    /// Salt is only present when the key was derived from a password, not a raw hex key.
    /// Decryptors must know whether a salt prefix is present (i.e. whether a password
    /// or a raw key was used).
    fn encrypt_data(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Encryption called without a key"))?;

        let cipher = Aes256Gcm::new_from_slice(key)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let mut result = Vec::new();
        if let Some(salt) = &self.encryption_salt {
            result.extend_from_slice(salt);
        }
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    async fn upload_records(
        &self,
        records: &[ConnectionRecord],
        batch_count: usize,
        timestamp: SystemTime,
        metadata: Option<CollectionMetadata>,
    ) -> anyhow::Result<()> {
        let client = self
            .upload_client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Upload client not initialized"))?;

        let url = self
            .opts
            .upload_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Upload URL not configured"))?;

        let hostname = hostname::get()?.to_string_lossy().to_string();
        let batch = UploadBatch {
            batch_id: format!("{}_{}", hostname, batch_count),
            hostname,
            timestamp,
            records: records.to_vec(),
            metadata,
        };

        let json_data = serde_json::to_string(&batch)?;

        let upload_data = if self.encryption_key.is_some() {
            let encrypted = self.encrypt_data(json_data.as_bytes())?;
            BASE64.encode(encrypted)
        } else {
            json_data
        };

        let mut request = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(upload_data);

        if let Some(api_key) = &self.opts.api_key {
            request = request.header("X-API-Key", api_key);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Upload failed: HTTP {}",
                response.status()
            ));
        }

        Ok(())
    }

    /// Returns the primary outbound local IP by routing a UDP socket toward a public
    /// address.  No packets are sent — UDP connect() just selects the interface.
    fn primary_local_ip() -> Option<String> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        Some(socket.local_addr().ok()?.ip().to_string())
    }

    fn generate_metadata(&self, start_time: SystemTime) -> anyhow::Result<CollectionMetadata> {
        let username = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .ok();

        Ok(CollectionMetadata {
            start_time,
            end_time: SystemTime::now(),
            hostname: hostname::get()?.to_string_lossy().to_string(),
            platform: std::env::consts::OS.to_string(),
            os_version: self.sys.long_os_version(),
            kernel_version: self.sys.kernel_version(),
            arch: std::env::consts::ARCH.to_string(),
            username,
            local_ip: Self::primary_local_ip(),
            total_records: self.total_records,
            unique_pids: self.unique_pids.len(),
            unique_remote_ips: self.unique_ips.len(),
            encrypted: self.encryption_key.is_some(),
            compressed: self.opts.compress,
        })
    }
}
