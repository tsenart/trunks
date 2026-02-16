use futures::Stream;
use hyper::body::to_bytes;
use hyper::client::connect::Connect;
use hyper::{Body, Client, Method, Request, Uri};
use std::collections::HashMap;

use std::pin::Pin;
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use tokio::io::AsyncBufRead;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::hit::Hit;
use crate::pacer::Pacer;
use crate::target::{Target, TargetRead, Targets};

#[derive(Debug)]
pub struct Attack<C, P: Pacer, R: AsyncBufRead + Send> {
    pub name: String,
    pub client: Client<C>,
    pub duration: Duration,
    pub pacer: Arc<P>,
    pub targets: Arc<Mutex<Targets<R>>>,
    pub workers: usize,
    pub max_workers: usize,
    pub timeout: Duration,
    pub max_body: i64,
    pub redirects: i32,
    pub chunked: bool,
    pub stop: CancellationToken,
}

impl<
        C: Connect + Clone + Send + Sync + 'static,
        P: Pacer + 'static,
        R: AsyncBufRead + Send + Sync + 'static,
    > Attack<C, P, R>
{
    pub fn run(&self) -> Pin<Box<impl Stream<Item = eyre::Result<Hit>>>> {
        // Bounded(1) channel acts like Go's unbuffered channel: sends block
        // until a worker is ready to receive, enabling backpressure and
        // dynamic worker scaling.
        let (target_send, target_recv) = async_channel::bounded::<(u64, Arc<Target>)>(1);
        let (hit_send, hit_recv) = async_channel::unbounded::<eyre::Result<Hit>>();

        for _ in 0..self.workers {
            tokio::spawn(worker(
                target_recv.clone(),
                hit_send.clone(),
                self.client.clone(),
                self.name.clone(),
                self.timeout,
                self.max_body,
                self.redirects,
                self.chunked,
            ));
        }

        tokio::spawn(attack(
            self.duration,
            self.pacer.clone(),
            self.targets.clone(),
            target_send,
            self.workers,
            self.max_workers,
            target_recv,
            hit_send,
            self.client.clone(),
            self.name.clone(),
            self.timeout,
            self.max_body,
            self.redirects,
            self.chunked,
            self.stop.clone(),
        ));

        Box::pin(hit_recv)
    }
}

#[allow(clippy::too_many_arguments)]
async fn worker<C: Connect + Clone + Send + Sync + 'static>(
    target_recv: async_channel::Receiver<(u64, Arc<Target>)>,
    hit_send: async_channel::Sender<eyre::Result<Hit>>,
    client: hyper::Client<C>,
    name: String,
    timeout: Duration,
    max_body: i64,
    redirects: i32,
    chunked: bool,
) {
    while let Ok((count, target)) = target_recv.recv().await {
        let result = hit(
            name.clone(),
            client.clone(),
            count,
            target,
            timeout,
            max_body,
            redirects,
            chunked,
        )
        .await;
        let _ = hit_send.send(result).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn attack<
    C: Connect + Clone + Send + Sync + 'static,
    P: Pacer,
    R: AsyncBufRead + Send + Sync,
>(
    duration: Duration,
    pacer: Arc<P>,
    targets: Arc<Mutex<Targets<R>>>,
    target_send: async_channel::Sender<(u64, Arc<Target>)>,
    workers: usize,
    max_workers: usize,
    target_recv: async_channel::Receiver<(u64, Arc<Target>)>,
    hit_send: async_channel::Sender<eyre::Result<Hit>>,
    client: hyper::Client<C>,
    name: String,
    timeout: Duration,
    max_body: i64,
    redirects: i32,
    chunked: bool,
    stop: CancellationToken,
) {
    let mut count: u64 = 0;
    let mut workers = workers;
    let began = Instant::now();
    let deadline = if duration.is_zero() {
        None
    } else {
        Some(tokio::time::Instant::now() + duration)
    };

    loop {
        if stop.is_cancelled() {
            break;
        }

        let elapsed = began.elapsed();
        if let Some(dl) = deadline {
            if tokio::time::Instant::now() >= dl {
                break;
            }
        }

        let (wait, pacer_stop) = pacer.pace(elapsed, count);
        if pacer_stop {
            break;
        }

        if !wait.is_zero() {
            if wait < MIN_SLEEP {
                tokio::task::yield_now().await;
                continue; // spin loop
            }
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = tokio::time::sleep(wait) => {}
            }
        }

        count += 1;
        let target = match targets.lock().await.decode().await {
            Ok(target) => target,
            Err(e) => {
                eprintln!("Error decoding target: {}", e);
                return;
            }
        };

        // Dynamic worker scaling: if all workers are busy (try_send fails)
        // and we haven't reached max_workers, spawn a new worker then fall
        // through to the blocking send. Mirrors vegeta's lib/attack.go.
        if workers < max_workers {
            match target_send.try_send((count, target)) {
                Ok(()) => continue,
                Err(async_channel::TrySendError::Full(pair)) => {
                    workers += 1;
                    tokio::spawn(worker(
                        target_recv.clone(),
                        hit_send.clone(),
                        client.clone(),
                        name.clone(),
                        timeout,
                        max_body,
                        redirects,
                        chunked,
                    ));
                    // Fall through to blocking send with the returned pair.
                    let target = pair.1;
                    if let Some(dl) = deadline {
                        tokio::select! {
                            _ = stop.cancelled() => break,
                            res = tokio::time::timeout_at(dl, target_send.send((count, target))) => {
                                if res.is_err() { break; }
                            }
                        }
                    } else {
                        tokio::select! {
                            _ = stop.cancelled() => break,
                            _ = target_send.send((count, target)) => {}
                        }
                    }
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(async_channel::TrySendError::Closed(_)) => break,
            }
        }

        // At max_workers: blocking send with deadline.
        if let Some(dl) = deadline {
            tokio::select! {
                _ = stop.cancelled() => break,
                res = tokio::time::timeout_at(dl, target_send.send((count, target))) => {
                    if res.is_err() { break; }
                }
            }
        } else {
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = target_send.send((count, target)) => {}
            }
        }

        tokio::task::yield_now().await;
    }
    // target_send and hit_send are dropped here, closing the channels.
    // Workers drain the bounded buffer (at most 1 item) and exit.
    // hit_recv stream ends when the last worker's hit_send clone drops.
}

#[cfg(unix)]
const MIN_SLEEP: Duration = Duration::from_millis(1);

#[cfg(windows)]
const MIN_SLEEP: Duration = Duration::from_millis(16);

// For any other OS not specifically handled above, use a safe default
#[cfg(not(any(unix, windows)))]
const MIN_SLEEP: Duration = Duration::from_millis(1);

fn is_redirect(status: hyper::StatusCode) -> bool {
    matches!(
        status,
        hyper::StatusCode::MOVED_PERMANENTLY
            | hyper::StatusCode::FOUND
            | hyper::StatusCode::SEE_OTHER
            | hyper::StatusCode::TEMPORARY_REDIRECT
            | hyper::StatusCode::PERMANENT_REDIRECT
    )
}

fn authority_of(uri: &Uri) -> String {
    uri.authority()
        .map(|a| a.as_str())
        .unwrap_or("")
        .to_string()
}

#[allow(clippy::too_many_arguments)]
async fn hit<C: Connect + Clone + Send + Sync + 'static>(
    attack: String,
    client: hyper::Client<C>,
    seq: u64,
    target: Arc<Target>,
    timeout: Duration,
    max_body: i64,
    redirects: i32,
    chunked: bool,
) -> eyre::Result<Hit> {
    let method = target.method.to_string();
    let url = target.url.to_string();
    let timestamp = SystemTime::now();
    let began = Instant::now();

    let mut current_method = target.method.clone();
    let mut current_uri = target.url.clone();
    let mut current_body = target.body.clone();
    let mut current_headers = target.headers.clone();
    let mut last_code: u16 = 0;
    let original_authority = authority_of(&target.url);

    for redirects_followed in 0..=redirects.max(0) as u32 {
        let mut req = Request::builder().method(&current_method).uri(&current_uri);
        if let Some(headers) = req.headers_mut() {
            *headers = current_headers.clone();
            if !attack.is_empty() {
                if let Ok(val) = hyper::header::HeaderValue::from_str(&attack) {
                    headers.insert(
                        hyper::header::HeaderName::from_static("x-trunks-attack"),
                        val,
                    );
                }
            }
            if let Ok(val) = hyper::header::HeaderValue::from_str(&seq.to_string()) {
                headers.insert(hyper::header::HeaderName::from_static("x-trunks-seq"), val);
            }
        }
        let body = if chunked && !current_body.is_empty() {
            let bytes = current_body.clone();
            Body::wrap_stream(futures::stream::once(async move {
                Ok::<_, std::io::Error>(bytes)
            }))
        } else {
            Body::from(current_body.clone())
        };
        let req = req.body(body)?;

        let res = if timeout.is_zero() {
            client.request(req).await
        } else {
            match tokio::time::timeout(timeout, client.request(req)).await {
                Ok(res) => res,
                Err(_) => {
                    return Ok(Hit {
                        attack,
                        seq,
                        code: 0,
                        timestamp,
                        latency: began.elapsed(),
                        bytes_out: 0,
                        bytes_in: 0,
                        error: "request timed out".to_string(),
                        body: vec![],
                        method,
                        url,
                        headers: HashMap::new(),
                    })
                }
            }
        };

        let res = match res {
            Ok(res) => res,
            Err(err) => {
                return Ok(Hit {
                    attack,
                    seq,
                    code: 0,
                    timestamp,
                    latency: began.elapsed(),
                    bytes_out: 0,
                    bytes_in: 0,
                    error: err.to_string(),
                    body: vec![],
                    method,
                    url,
                    headers: HashMap::new(),
                })
            }
        };

        let status = res.status();
        last_code = status.as_u16();

        if !is_redirect(status) || redirects < 0 {
            let response_headers: HashMap<String, Vec<String>> =
                res.headers()
                    .iter()
                    .fold(HashMap::new(), |mut map, (name, value)| {
                        map.entry(name.as_str().to_string())
                            .or_default()
                            .push(value.to_str().unwrap_or("").to_string());
                        map
                    });
            let mut body = to_bytes(res.into_body()).await?.to_vec();
            if max_body >= 0 {
                body.truncate(max_body as usize);
            }

            return Ok(Hit {
                attack,
                seq,
                code: last_code,
                timestamp,
                latency: began.elapsed(),
                bytes_out: current_body.len() as u64,
                bytes_in: body.len() as u64,
                error: String::default(),
                body,
                method,
                url,
                headers: response_headers,
            });
        }

        if redirects_followed == redirects as u32 {
            let _ = to_bytes(res.into_body()).await?;
            break;
        }

        let location = match res.headers().get(hyper::header::LOCATION) {
            Some(loc) => loc.to_str()?.to_string(),
            None => {
                let _ = to_bytes(res.into_body()).await?;
                break;
            }
        };

        let _ = to_bytes(res.into_body()).await?;

        current_uri = resolve_redirect(&current_uri, &location)?;

        // Strip sensitive headers on cross-authority redirects.
        let new_authority = authority_of(&current_uri);
        if new_authority != original_authority {
            current_headers.remove(hyper::header::AUTHORIZATION);
            current_headers.remove(hyper::header::COOKIE);
        }

        // 301/302: POST → GET and drop body (matching Go net/http behavior).
        // 303: any method → GET and drop body.
        match status {
            hyper::StatusCode::MOVED_PERMANENTLY | hyper::StatusCode::FOUND => {
                if current_method == Method::POST {
                    current_method = Method::GET;
                    current_body = hyper::body::Bytes::new();
                }
            }
            hyper::StatusCode::SEE_OTHER => {
                current_method = Method::GET;
                current_body = hyper::body::Bytes::new();
            }
            _ => {} // 307/308 preserve method and body
        }
    }

    Ok(Hit {
        attack,
        seq,
        code: last_code,
        timestamp,
        latency: began.elapsed(),
        bytes_out: current_body.len() as u64,
        bytes_in: 0,
        error: format!("stopped after {} redirects", redirects),
        body: vec![],
        method,
        url,
        headers: HashMap::new(),
    })
}

fn resolve_redirect(base: &Uri, location: &str) -> eyre::Result<Uri> {
    let base_url = Url::parse(&base.to_string())
        .map_err(|e| eyre::eyre!("invalid base URL {:?}: {}", base, e))?;
    let resolved = base_url
        .join(location)
        .map_err(|e| eyre::eyre!("invalid redirect location {:?}: {}", location, e))?;
    Ok(resolved.as_str().parse::<Uri>()?)
}
