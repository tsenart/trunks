use hyper::client::connect::dns::Name;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tower_service::Service;

/// Iterator over resolved socket addresses.
pub struct Addrs {
    iter: std::vec::IntoIter<SocketAddr>,
}

impl Iterator for Addrs {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

/// Custom DNS resolver supporting:
/// - Address remapping via `--connect-to` (round-robin across targets)
/// - DNS caching with configurable TTL via `--dns-ttl`
/// - Custom DNS servers via `--resolvers`
#[derive(Clone)]
pub struct TrunksResolver {
    connect_to: Arc<HashMap<String, RoundRobin>>,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    ttl: Option<Duration>,
    resolvers: Arc<Vec<SocketAddr>>,
    resolver_idx: Arc<AtomicUsize>,
}

struct RoundRobin {
    addrs: Vec<String>,
    index: AtomicUsize,
}

impl Clone for RoundRobin {
    fn clone(&self) -> Self {
        RoundRobin {
            addrs: self.addrs.clone(),
            index: AtomicUsize::new(self.index.load(Ordering::Relaxed)),
        }
    }
}

#[derive(Clone)]
struct CacheEntry {
    addrs: Vec<SocketAddr>,
    created: Instant,
}

/// Global atomic counter for DNS query IDs.
static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);

impl TrunksResolver {
    pub fn new(
        connect_to: HashMap<String, Vec<String>>,
        ttl: Option<Duration>,
        resolvers: Vec<String>,
    ) -> Self {
        let connect_to = connect_to
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    RoundRobin {
                        addrs: v,
                        index: AtomicUsize::new(0),
                    },
                )
            })
            .collect();

        let resolvers = resolvers
            .into_iter()
            .filter_map(|s| normalize_resolver_addr(&s))
            .collect();

        TrunksResolver {
            connect_to: Arc::new(connect_to),
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            resolvers: Arc::new(resolvers),
            resolver_idx: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Normalize a resolver address string to a SocketAddr.
/// Accepts "ip", "ip:port". Default port is 53.
/// Returns None if the host part is not a valid IP address.
fn normalize_resolver_addr(s: &str) -> Option<SocketAddr> {
    // Try parsing as a full socket address first (ip:port)
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr);
    }
    // Try parsing as an IP address (no port)
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    // Try [ipv6]:port format
    if s.starts_with('[') {
        if let Some(idx) = s.rfind("]:") {
            let ip_str = &s[1..idx];
            let port_str = &s[idx + 2..];
            if let (Ok(ip), Ok(port)) = (ip_str.parse::<IpAddr>(), port_str.parse::<u16>()) {
                return Some(SocketAddr::new(ip, port));
            }
        }
    }
    None
}

/// Build a DNS query packet for the given name and query type (A=1, AAAA=28).
fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let id = DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let mut buf = Vec::with_capacity(512);
    // Header
    buf.extend_from_slice(&id.to_be_bytes()); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
                                          // Question: encode domain name as labels
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // root label
    buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    buf
}

/// Parse a DNS response and extract IP addresses from answer records.
fn parse_dns_response(resp: &[u8]) -> io::Result<Vec<IpAddr>> {
    if resp.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response too short",
        ));
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    // Skip header (12 bytes), then skip question section
    let mut pos = 12;
    // Skip question name
    pos = skip_dns_name(resp, pos)?;
    // Skip QTYPE (2) + QCLASS (2)
    pos += 4;
    if pos > resp.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response truncated in question",
        ));
    }

    let mut addrs = Vec::new();
    for _ in 0..ancount {
        if pos >= resp.len() {
            break;
        }
        // Skip answer name (may be compressed pointer)
        pos = skip_dns_name(resp, pos)?;
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        // skip TYPE(2) + CLASS(2) + TTL(4)
        pos += 8;
        let rdlength = u16::from_be_bytes([resp[pos], resp[pos + 1]]) as usize;
        pos += 2;
        if pos + rdlength > resp.len() {
            break;
        }
        match (rtype, rdlength) {
            (1, 4) => {
                // A record
                let ip = Ipv4Addr::new(resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]);
                addrs.push(IpAddr::V4(ip));
            }
            (28, 16) => {
                // AAAA record
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&resp[pos..pos + 16]);
                addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += rdlength;
    }
    Ok(addrs)
}

/// Skip a DNS name at the given position, handling label compression.
fn skip_dns_name(resp: &[u8], mut pos: usize) -> io::Result<usize> {
    loop {
        if pos >= resp.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS name out of bounds",
            ));
        }
        let len = resp[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compressed pointer: 2 bytes total, we're done
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    Ok(pos)
}

/// Resolve a hostname using a custom DNS server via UDP.
/// Sends both A and AAAA queries and combines results.
fn dns_resolve(name: &str, server_addr: SocketAddr) -> io::Result<Vec<IpAddr>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.connect(server_addr)?;

    let mut all_addrs = Vec::new();

    // A query
    let query = build_dns_query(name, 1);
    socket.send(&query)?;
    let mut resp = [0u8; 4096];
    let len = socket.recv(&mut resp)?;
    if let Ok(addrs) = parse_dns_response(&resp[..len]) {
        all_addrs.extend(addrs);
    }

    // AAAA query
    let query = build_dns_query(name, 28);
    socket.send(&query)?;
    let len = socket.recv(&mut resp)?;
    if let Ok(addrs) = parse_dns_response(&resp[..len]) {
        all_addrs.extend(addrs);
    }

    Ok(all_addrs)
}

impl Service<Name> for TrunksResolver {
    type Response = Addrs;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Addrs, io::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let host = name.as_str().to_string();
        let connect_to = self.connect_to.clone();
        let cache = self.cache.clone();
        let ttl = self.ttl;
        let resolvers = self.resolvers.clone();
        let resolver_idx = self.resolver_idx.clone();

        Box::pin(async move {
            // Check --connect-to remapping
            if let Some(rr) = connect_to.get(&host) {
                let idx = rr.index.fetch_add(1, Ordering::Relaxed) % rr.addrs.len();
                let target = &rr.addrs[idx];
                // Resolve the remapped target via blocking getaddrinfo
                let target = target.clone();
                let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
                    (target.as_str(), 0u16)
                        .to_socket_addrs()
                        .map(|iter| iter.collect::<Vec<_>>())
                })
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;
                if !addrs.is_empty() {
                    return Ok(Addrs {
                        iter: addrs.into_iter(),
                    });
                }
            }

            // Check DNS cache
            if let Some(ttl_dur) = ttl {
                let cache_read = cache.read().unwrap();
                if let Some(entry) = cache_read.get(&host) {
                    if ttl_dur.is_zero() || entry.created.elapsed() < ttl_dur {
                        return Ok(Addrs {
                            iter: entry.addrs.clone().into_iter(),
                        });
                    }
                }
                drop(cache_read);
            }

            // DNS resolution: custom resolvers or system getaddrinfo
            let addrs: Vec<SocketAddr> = if !resolvers.is_empty() {
                let idx = resolver_idx.fetch_add(1, Ordering::Relaxed) % resolvers.len();
                let server = resolvers[idx];
                let host_clone = host.clone();
                let ips = tokio::task::spawn_blocking(move || dns_resolve(&host_clone, server))
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;
                ips.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect()
            } else {
                let host_clone = host.clone();
                tokio::task::spawn_blocking(move || {
                    (host_clone.as_str(), 0u16)
                        .to_socket_addrs()
                        .map(|iter| iter.collect::<Vec<_>>())
                })
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??
            };

            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("no addresses found for {}", host),
                ));
            }

            // Store in cache if TTL is configured
            if ttl.is_some() {
                let mut cache_write = cache.write().unwrap();
                cache_write.insert(
                    host,
                    CacheEntry {
                        addrs: addrs.clone(),
                        created: Instant::now(),
                    },
                );
            }

            Ok(Addrs {
                iter: addrs.into_iter(),
            })
        })
    }
}
