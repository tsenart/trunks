use hyper::client::connect::dns::Name;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
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
/// Returns (query_bytes, transaction_id).
fn build_dns_query(name: &str, qtype: u16) -> (Vec<u8>, u16) {
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
    (buf, id)
}

/// Parse a DNS response and extract IP addresses from answer records.
/// Validates the transaction ID matches the expected query ID.
fn parse_dns_response(resp: &[u8], expected_id: u16) -> io::Result<Vec<IpAddr>> {
    if resp.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response too short",
        ));
    }
    let resp_id = u16::from_be_bytes([resp[0], resp[1]]);
    if resp_id != expected_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "DNS transaction ID mismatch: expected {}, got {}",
                expected_id, resp_id
            ),
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

/// Resolve a hostname using a custom DNS server via async UDP.
/// Sends both A and AAAA queries and combines results.
async fn dns_resolve_async(name: &str, server_addr: SocketAddr) -> io::Result<Vec<IpAddr>> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(server_addr).await?;

    let mut all_addrs = Vec::new();

    // A query
    let (query, query_id) = build_dns_query(name, 1);
    socket.send(&query).await?;
    let mut resp = [0u8; 4096];
    let len = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut resp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))??;
    if let Ok(addrs) = parse_dns_response(&resp[..len], query_id) {
        all_addrs.extend(addrs);
    }

    // AAAA query
    let (query, query_id) = build_dns_query(name, 28);
    socket.send(&query).await?;
    let len = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut resp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS AAAA query timed out"))??;
    if let Ok(addrs) = parse_dns_response(&resp[..len], query_id) {
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
                let ips = dns_resolve_async(&host, server).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ipv4_no_port() {
        let addr = normalize_resolver_addr("8.8.8.8").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(addr.port(), 53);
    }

    #[test]
    fn normalize_ipv4_with_port() {
        let addr = normalize_resolver_addr("8.8.8.8:5353").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(addr.port(), 5353);
    }

    #[test]
    fn normalize_ipv6_no_port() {
        let addr = normalize_resolver_addr("::1").unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(addr.port(), 53);
    }

    #[test]
    fn normalize_ipv6_bracket_port() {
        let addr = normalize_resolver_addr("[::1]:5353").unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(addr.port(), 5353);
    }

    #[test]
    fn normalize_invalid() {
        assert!(normalize_resolver_addr("not-an-ip").is_none());
    }

    #[test]
    fn build_dns_query_structure() {
        let (q, id) = build_dns_query("example.com", 1);
        assert!(q.len() > 12);
        // ID matches returned value
        assert_eq!(u16::from_be_bytes([q[0], q[1]]), id);
        // QDCOUNT = 1
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        // ANCOUNT = 0
        assert_eq!(&q[6..8], &[0x00, 0x00]);
        // Question: label "example" (len 7)
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        // Label "com" (len 3)
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        // Root label
        assert_eq!(q[24], 0);
        // QTYPE = A (1)
        assert_eq!(&q[25..27], &[0x00, 0x01]);
        // QCLASS = IN (1)
        assert_eq!(&q[27..29], &[0x00, 0x01]);
    }

    #[test]
    fn build_dns_query_aaaa() {
        let (q, _id) = build_dns_query("test.io", 28);
        // Find QTYPE at end: after root label (0), next 2 bytes are QTYPE
        // "test" = 4 bytes + 1 len, "io" = 2 bytes + 1 len, root = 1 byte
        // offset = 12 + 1+4 + 1+2 + 1 = 21, QTYPE at 21..23
        assert_eq!(q[21], 0x00);
        assert_eq!(q[22], 0x1C); // 28
    }

    #[test]
    fn parse_dns_response_a_record() {
        let mut resp = Vec::new();
        // Header
        resp.extend_from_slice(&[0x00, 0x01]); // ID=1
        resp.extend_from_slice(&[0x81, 0x80]); // Flags
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
                                               // Question: example.com
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        resp.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
                                               // Answer: compressed pointer to name at offset 12
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL=300
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        resp.extend_from_slice(&[1, 2, 3, 4]); // RDATA

        let addrs = parse_dns_response(&resp, 1).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn parse_dns_response_too_short() {
        assert!(parse_dns_response(&[0u8; 5], 0).is_err());
    }

    #[test]
    fn skip_dns_name_labels() {
        let data = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let pos = skip_dns_name(&data, 0).unwrap();
        assert_eq!(pos, 13);
    }

    #[test]
    fn skip_dns_name_compressed() {
        let data = [0xC0, 0x0C];
        let pos = skip_dns_name(&data, 0).unwrap();
        assert_eq!(pos, 2);
    }

    #[test]
    fn parse_dns_response_validates_transaction_id() {
        // Build a DNS query so we know the expected ID
        let (_query, expected_id) = build_dns_query("example.com", 1);

        // Build a valid A-record response but with a WRONG transaction ID
        let wrong_id = expected_id.wrapping_add(1);
        let mut resp = Vec::new();
        resp.extend_from_slice(&wrong_id.to_be_bytes()); // Wrong ID
        resp.extend_from_slice(&[0x81, 0x80]); // Flags
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
                                               // Question: example.com
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        resp.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
                                               // Answer
        resp.extend_from_slice(&[0xC0, 0x0C]); // Compressed name
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        resp.extend_from_slice(&[1, 2, 3, 4]); // RDATA

        // Should reject: wrong transaction ID
        let result = parse_dns_response(&resp, expected_id);
        assert!(
            result.is_err(),
            "should reject response with wrong transaction ID"
        );

        // Should accept: correct transaction ID
        let mut resp_ok = resp.clone();
        resp_ok[0..2].copy_from_slice(&expected_id.to_be_bytes());
        let addrs = parse_dns_response(&resp_ok, expected_id).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn build_dns_query_returns_unique_ids() {
        let (_q1, id1) = build_dns_query("a.com", 1);
        let (_q2, id2) = build_dns_query("b.com", 1);
        assert_ne!(id1, id2, "each query should have a unique transaction ID");
    }

    #[tokio::test]
    async fn async_dns_resolve_uses_tokio_udp() {
        // This test validates that dns_resolve is async (takes tokio UdpSocket).
        // We bind a local UDP socket that echoes a valid DNS response,
        // then call dns_resolve_async to verify it works without spawn_blocking.
        use tokio::net::UdpSocket as TokioUdpSocket;

        let server = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Spawn a mock DNS server that replies to one A query
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            // Build response: copy query ID, set response flags, 1 answer
            let mut resp = Vec::new();
            resp.extend_from_slice(&buf[0..2]); // Copy query ID
            resp.extend_from_slice(&[0x81, 0x80]); // Response flags
            resp.extend_from_slice(&buf[4..6]); // QDCOUNT
            resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
            resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
            resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
            resp.extend_from_slice(&buf[12..len]); // Copy question
                                                   // Answer: compressed pointer, A record
            resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
            resp.extend_from_slice(&[0x00, 0x01]); // TYPE=A
            resp.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
            resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
            resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
            resp.extend_from_slice(&[10, 0, 0, 1]); // 10.0.0.1
            server.send_to(&resp, peer).await.unwrap();

            // Handle AAAA query too
            let (len2, peer2) = server.recv_from(&mut buf).await.unwrap();
            let mut resp2 = Vec::new();
            resp2.extend_from_slice(&buf[0..2]); // Copy query ID
            resp2.extend_from_slice(&[0x81, 0x80]); // Response flags
            resp2.extend_from_slice(&buf[4..6]); // QDCOUNT
            resp2.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0 (no AAAA)
            resp2.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
            resp2.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
            resp2.extend_from_slice(&buf[12..len2]); // Copy question
            server.send_to(&resp2, peer2).await.unwrap();
        });

        let ips = dns_resolve_async("test.example", server_addr)
            .await
            .unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        handle.await.unwrap();
    }
}
