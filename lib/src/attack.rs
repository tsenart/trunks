use futures::Stream;
use hyper::body::to_bytes;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Request};
use hyper_rustls::HttpsConnector;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use tokio::io::AsyncBufRead;
use tokio::sync::Mutex;
use tokio::time::Duration;

use crate::hit::Hit;
use crate::pacer::Pacer;
use crate::target::{Target, TargetRead, Targets};

#[derive(Debug)]
pub struct Attack<P: Pacer, R: AsyncBufRead + Send> {
    pub name: String,
    pub client: Client<HttpsConnector<HttpConnector>>,
    pub duration: Duration,
    pub pacer: Arc<P>,
    pub targets: Arc<Mutex<Targets<R>>>,
    pub workers: usize,
    pub max_workers: usize,
    pub timeout: Duration,
    pub max_body: i64,
}

impl<P: Pacer + 'static, R: AsyncBufRead + Send + Sync + 'static> Attack<P, R> {
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
        ));

        Box::pin(hit_recv)
    }
}

async fn worker(
    target_recv: async_channel::Receiver<(u64, Arc<Target>)>,
    hit_send: async_channel::Sender<eyre::Result<Hit>>,
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    name: String,
    timeout: Duration,
    max_body: i64,
) {
    while let Ok((count, target)) = target_recv.recv().await {
        let result = hit(name.clone(), client.clone(), count, target, timeout, max_body).await;
        let _ = hit_send.send(result).await;
    }
}

async fn attack<P: Pacer, R: AsyncBufRead + Send + Sync>(
    duration: Duration,
    pacer: Arc<P>,
    targets: Arc<Mutex<Targets<R>>>,
    target_send: async_channel::Sender<(u64, Arc<Target>)>,
    workers: usize,
    max_workers: usize,
    target_recv: async_channel::Receiver<(u64, Arc<Target>)>,
    hit_send: async_channel::Sender<eyre::Result<Hit>>,
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    name: String,
    timeout: Duration,
    max_body: i64,
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
        let elapsed = began.elapsed();
        if let Some(dl) = deadline {
            if tokio::time::Instant::now() >= dl {
                break;
            }
        }

        let (wait, stop) = pacer.pace(elapsed, count);
        if stop {
            break;
        }

        if !wait.is_zero() {
            if wait < MIN_SLEEP {
                tokio::task::yield_now().await;
                continue; // spin loop
            }
            tokio::time::sleep(wait).await;
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
                    ));
                    // Fall through to blocking send with the returned pair.
                    let target = pair.1;
                    if let Some(dl) = deadline {
                        if tokio::time::timeout_at(dl, target_send.send((count, target)))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    } else {
                        let _ = target_send.send((count, target)).await;
                    }
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(async_channel::TrySendError::Closed(_)) => break,
            }
        }

        // At max_workers: blocking send with deadline.
        if let Some(dl) = deadline {
            if tokio::time::timeout_at(dl, target_send.send((count, target)))
                .await
                .is_err()
            {
                break;
            }
        } else {
            let _ = target_send.send((count, target)).await;
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

async fn hit(
    attack: String,
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    seq: u64,
    target: Arc<Target>,
    timeout: Duration,
    max_body: i64,
) -> eyre::Result<Hit> {
    let method = target.method.to_string();
    let url = target.url.to_string();
    let timestamp = SystemTime::now();
    let began = Instant::now();
    let mut req = Request::builder().method(&target.method).uri(&target.url);
    if let Some(headers) = req.headers_mut() {
        *headers = target.headers.clone();
    }
    let req = req.body(Body::from(target.body.clone()))?;

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
            })
        }
    };

    let code = res.status().as_u16();
    let mut body = to_bytes(res.into_body()).await?.to_vec();
    if max_body >= 0 {
        body.truncate(max_body as usize);
    }
    let latency = began.elapsed();

    Ok(Hit {
        attack,
        seq,
        code,
        timestamp,
        latency,
        bytes_out: target.body.len() as u64,
        bytes_in: body.len() as u64,
        error: String::default(),
        body,
        method,
        url,
    })
}
