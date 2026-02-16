use hyper::client::connect::dns::Name;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
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
#[derive(Clone)]
pub struct TrunksResolver {
    connect_to: Arc<HashMap<String, RoundRobin>>,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    ttl: Option<Duration>,
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

impl TrunksResolver {
    pub fn new(connect_to: HashMap<String, Vec<String>>, ttl: Option<Duration>) -> Self {
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
        TrunksResolver {
            connect_to: Arc::new(connect_to),
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }
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

            // Standard DNS resolution
            let host_clone = host.clone();
            let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
                (host_clone.as_str(), 0u16)
                    .to_socket_addrs()
                    .map(|iter| iter.collect::<Vec<_>>())
            })
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;

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
