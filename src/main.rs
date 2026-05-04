// pqfetch. TLS post-quantum readiness scanner.
//
// connects to each host with a rustls client that prefers post-quantum
// hybrid key exchange (X25519MLKEM768), then reports the actually
// negotiated key-exchange group + TLS version. tells you in one line
// whether a server you care about has the hybrid kex turned on.
//
//   pqfetch cloudflare.com google.com github.com
//                          tls   kx                     pq?
//   cloudflare.com         1.3   X25519MLKEM768         yes
//   google.com             1.3   X25519                 no
//   github.com             1.3   X25519                 no
//
// motivation: the IETF TLS WG ships X25519MLKEM768 (codepoint 0x11ec)
// as the canonical hybrid post-quantum kex. browsers and a handful of
// edge networks (cloudflare, google) have it enabled. most other
// servers are still classical. this binary tells you which is which
// without reading wireshark dumps.

#![allow(clippy::needless_pass_by_value)]

use anyhow::Result;
use clap::Parser;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "pqfetch",
    about = "TLS post-quantum readiness scanner",
    version
)]
struct Cli {
    /// hosts to scan, e.g. cloudflare.com or example.com:8443
    hosts: Vec<String>,
    /// scan a built-in curated list (cloudflare/google/github/etc) when no
    /// hosts are supplied
    #[arg(long)]
    curated: bool,
    /// connect timeout in seconds (default 4)
    #[arg(long, default_value_t = 4u64)]
    timeout: u64,
    /// emit one JSON object per line instead of the human table
    #[arg(long)]
    json: bool,
}

const CURATED: &[&str] = &[
    "cloudflare.com",
    "google.com",
    "youtube.com",
    "github.com",
    "amazon.com",
    "apple.com",
    "microsoft.com",
    "openai.com",
    "anthropic.com",
    "meta.com",
    "facebook.com",
    "x.com",
    "wikipedia.org",
    "stackoverflow.com",
    "rust-lang.org",
    "crates.io",
    "docs.rs",
];

#[derive(Debug, Clone)]
struct Probe {
    host: String,
    port: u16,
    tls_version: Option<&'static str>,
    kex_group: Option<&'static str>,
    error: Option<String>,
}

impl Probe {
    fn pq(&self) -> bool {
        match self.kex_group {
            Some(g) => g.contains("MLKEM") || g.contains("ML-KEM") || g.contains("Kyber"),
            None => false,
        }
    }
}

fn parse_target(s: &str) -> (String, u16) {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (s.to_string(), 443)
}

fn build_config() -> Arc<ClientConfig> {
    // install aws-lc-rs as the default crypto provider. with the
    // `prefer-post-quantum` rustls feature on, the provider advertises
    // X25519MLKEM768 ahead of classical X25519 in the client hello,
    // so any server that supports the hybrid will negotiate it.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

fn probe_one(cfg: Arc<ClientConfig>, host: String, port: u16, timeout: Duration) -> Probe {
    let mut p = Probe {
        host: host.clone(),
        port,
        tls_version: None,
        kex_group: None,
        error: None,
    };

    // resolve + connect with timeout
    let addrs: Vec<_> = match (host.as_str(), port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => {
            p.error = Some(format!("dns: {e}"));
            return p;
        }
    };
    if addrs.is_empty() {
        p.error = Some("dns: no addresses".to_string());
        return p;
    }
    let mut sock = match TcpStream::connect_timeout(&addrs[0], timeout) {
        Ok(s) => s,
        Err(e) => {
            p.error = Some(format!("tcp: {e}"));
            return p;
        }
    };
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));

    let server_name = match ServerName::try_from(host.clone()) {
        Ok(n) => n,
        Err(e) => {
            p.error = Some(format!("sni: {e}"));
            return p;
        }
    };

    let mut conn = match ClientConnection::new(cfg, server_name) {
        Ok(c) => c,
        Err(e) => {
            p.error = Some(format!("rustls: {e}"));
            return p;
        }
    };

    // drive the handshake
    while conn.is_handshaking() {
        if conn.wants_write() {
            if let Err(e) = conn.write_tls(&mut sock) {
                p.error = Some(format!("write: {e}"));
                return p;
            }
        }
        if conn.wants_read() {
            match conn.read_tls(&mut sock) {
                Ok(0) => {
                    p.error = Some("eof during handshake".to_string());
                    return p;
                }
                Ok(_) => {}
                Err(e) => {
                    p.error = Some(format!("read: {e}"));
                    return p;
                }
            }
            if let Err(e) = conn.process_new_packets() {
                p.error = Some(format!("tls: {e}"));
                return p;
            }
        }
    }

    p.tls_version = conn.protocol_version().map(version_str);
    p.kex_group = conn
        .negotiated_key_exchange_group()
        .map(|g| named_group_str(g.name()));

    // close cleanly
    conn.send_close_notify();
    let _ = conn.write_tls(&mut sock);

    p
}

fn version_str(v: rustls::ProtocolVersion) -> &'static str {
    use rustls::ProtocolVersion;
    match v {
        ProtocolVersion::TLSv1_3 => "1.3",
        ProtocolVersion::TLSv1_2 => "1.2",
        ProtocolVersion::TLSv1_1 => "1.1",
        ProtocolVersion::TLSv1_0 => "1.0",
        _ => "?",
    }
}

fn named_group_str(g: rustls::NamedGroup) -> &'static str {
    match u16::from(g) {
        0x001d => "X25519",
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001e => "X448",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x11ec => "X25519MLKEM768",
        0x6399 => "X25519Kyber768Draft00",
        0x6398 => "Kyber768Draft00",
        _ => "?",
    }
}

fn print_table(probes: &[Probe]) {
    let host_w = probes
        .iter()
        .map(|p| display_host(p).len())
        .max()
        .unwrap_or(8)
        .max(8);
    let kx_w = probes
        .iter()
        .map(|p| p.kex_group.unwrap_or("").len())
        .max()
        .unwrap_or(20)
        .max(15);
    println!(
        "{:width$}  {:>4}  {:<kw$}  {:>3}",
        "host",
        "tls",
        "kx",
        "pq?",
        width = host_w,
        kw = kx_w
    );
    for p in probes {
        if let Some(err) = &p.error {
            println!(
                "{:width$}  {:>4}  {:<kw$}  {:>3}",
                display_host(p),
                "-",
                err,
                "-",
                width = host_w,
                kw = kx_w
            );
            continue;
        }
        println!(
            "{:width$}  {:>4}  {:<kw$}  {:>3}",
            display_host(p),
            p.tls_version.unwrap_or("?"),
            p.kex_group.unwrap_or("?"),
            if p.pq() { "yes" } else { "no" },
            width = host_w,
            kw = kx_w
        );
    }
}

fn display_host(p: &Probe) -> String {
    if p.port == 443 {
        p.host.clone()
    } else {
        format!("{}:{}", p.host, p.port)
    }
}

fn print_json(probes: &[Probe]) {
    for p in probes {
        let mut s = String::from("{");
        s.push_str(&format!("\"host\":\"{}\"", p.host));
        s.push_str(&format!(",\"port\":{}", p.port));
        if let Some(v) = p.tls_version {
            s.push_str(&format!(",\"tls\":\"{}\"", v));
        }
        if let Some(g) = p.kex_group {
            s.push_str(&format!(",\"kex\":\"{}\"", g));
        }
        s.push_str(&format!(",\"pq\":{}", p.pq()));
        if let Some(e) = &p.error {
            s.push_str(&format!(
                ",\"error\":\"{}\"",
                e.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }
        s.push('}');
        println!("{}", s);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let timeout = Duration::from_secs(cli.timeout);

    let targets: Vec<(String, u16)> = if cli.hosts.is_empty() {
        if !cli.curated {
            eprintln!("usage: pqfetch <host>... | pqfetch --curated");
            std::process::exit(2);
        }
        CURATED.iter().map(|h| ((*h).to_string(), 443)).collect()
    } else {
        cli.hosts.iter().map(|s| parse_target(s)).collect()
    };

    let cfg = build_config();
    let mut probes: Vec<Probe> = Vec::with_capacity(targets.len());

    // sequential is fine for the curated list size, simpler than rayon
    // for the binary footprint.
    for (host, port) in targets {
        let p = probe_one(cfg.clone(), host, port, timeout);
        probes.push(p);
    }

    if cli.json {
        print_json(&probes);
    } else {
        print_table(&probes);
    }

    let any_pq = probes.iter().any(Probe::pq);
    if !any_pq && !cli.json {
        eprintln!();
        eprintln!(
            "no host in this set negotiated a post-quantum hybrid kex. \
             try `--curated` for a list that includes hosts known to ship pq."
        );
    }

    Ok(())
}
