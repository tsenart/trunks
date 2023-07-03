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
// use tokio_util::sync::CancellationToken;

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
}

impl<P: Pacer + 'static, R: AsyncBufRead + Send + Sync + 'static> Attack<P, R> {
    pub fn run(&self) -> Pin<Box<impl Stream<Item = eyre::Result<Hit>>>> {
        let (send, recv) = async_channel::unbounded::<eyre::Result<Hit>>();
        let duration = self.duration;
        let client = self.client.clone();
        let name = self.name.clone();
        let pacer = self.pacer.clone();
        let targets = self.targets.clone();

        tokio::spawn(async move { attack(duration, pacer, targets, name, client, send).await });

        Box::pin(recv)
    }
}

#[cfg(unix)]
const MIN_SLEEP: Duration = Duration::from_millis(1);

#[cfg(windows)]
const MIN_SLEEP: Duration = Duration::from_millis(16);

// For any other OS not specifically handled above, use a safe default
#[cfg(not(any(unix, windows)))]
const MIN_SLEEP: Duration = Duration::from_millis(1);

async fn attack<P: Pacer, R: AsyncBufRead + Send + Sync>(
    duration: Duration,
    pacer: Arc<P>,
    targets: Arc<Mutex<Targets<R>>>,
    name: String,
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    send: async_channel::Sender<eyre::Result<Hit>>,
) {
    let mut count: u64 = 0;
    let began = Instant::now();

    loop {
        let elapsed = began.elapsed();
        if !duration.is_zero() && elapsed > duration {
            break;
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
        match targets.lock().await.decode().await {
            Ok(target) => {
                let name = name.clone();
                let client = client.clone();
                let send = send.clone();
                tokio::spawn(async move {
                    let result = hit(name, client, count, target).await;
                    let _ = send.send(result).await;
                });
            }

            Err(e) => {
                let _ = send.send(Err(e)).await;
            }
        }

        tokio::task::yield_now().await;
    }
}

async fn hit(
    attack: String,
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    seq: u64,
    target: Arc<Target>,
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
    let res = match client.request(req).await {
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
    let body = to_bytes(res.into_body()).await?.to_vec();
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
