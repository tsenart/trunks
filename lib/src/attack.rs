use futures::Stream;
use reqwest::Client;
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
    pub client: Client,
    pub duration: Duration,
    pub pacer: Arc<P>,
    pub targets: Arc<Mutex<Targets<R>>>,
}

impl<P: Pacer + 'static, R: AsyncBufRead + Send + Sync + 'static> Attack<P, R> {
    pub fn run(&self) -> Pin<Box<impl Stream<Item = eyre::Result<Hit>>>> {
        let (send, recv) = async_channel::unbounded::<eyre::Result<Hit>>();
        let duration = self.duration.clone();
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
    client: reqwest::Client,
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
        let mut target: Target = Default::default();
        match targets.lock().await.decode(&mut target).await {
            Ok(_) => {
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
    client: reqwest::Client,
    seq: u64,
    target: Target,
) -> eyre::Result<Hit> {
    let req = target.request()?;
    let timestamp = SystemTime::now();
    let began = Instant::now();
    let res = client.execute(req).await?;
    let code = res.status().as_u16();
    let body = res.bytes().await?.to_vec();
    let latency = began.elapsed();

    Ok(Hit {
        attack,
        seq,
        code,
        timestamp,
        latency,
        body,
        method: target.method.to_string(),
        url: target.url.to_string(),
    })
}
