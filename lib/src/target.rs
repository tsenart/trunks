use async_trait::async_trait;
use eyre::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::io::Error as IoError;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Target {
    pub req: hyper::Request<Vec<u8>>,
}

#[async_trait]
pub trait TargetRead<R: AsyncBufRead> {
    async fn decode(&mut self, target: &mut Target) -> Result<()>;
}

#[derive(Default, Debug, Clone)]
pub enum Targets<R: AsyncBufRead + Send> {
    #[default]
    None,
    Static {
        pos: Arc<AtomicUsize>,
        targets: Vec<Target>,
    },
    Lazy(TargetReader<R>),
}

impl<'a, R: AsyncBufRead + Send> From<Vec<Target>> for Targets<R> {
    fn from(targets: Vec<Target>) -> Self {
        Self::Static {
            pos: Arc::new(AtomicUsize::new(0)),
            targets,
        }
    }
}

#[async_trait]
impl<'a, R: AsyncBufRead + Send> TargetRead<R> for Targets<R> {
    async fn decode(&mut self, target: &mut Target) -> Result<()> {
        match self {
            Targets::None => eyre::bail!("no targets"),
            Targets::Static { pos, targets } => {
                if targets.is_empty() {
                    eyre::bail!("no targets")
                }
                *target = targets[pos.fetch_add(1, Ordering::SeqCst) % targets.len()].clone();
                Ok(())
            }
            Targets::Lazy(reader) => reader.decode(target).await,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TargetDefaults {
    pub headers: HashMap<String, Vec<String>>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum TargetReader<R: AsyncBufRead> {
    Json(Pin<Box<(R, TargetDefaults)>>),
    Http(Pin<Box<(R, TargetDefaults)>>),
}

impl<R: AsyncBufRead> TargetReader<R> {
    pub fn new(format: &str, source: R) -> Result<Self> {
        match format {
            "json" => Ok(TargetReader::Json(Box::pin(source))),
            "http" => Ok(TargetReader::Http(Box::pin(source))),
            _ => eyre::bail!("invalid target format: {}", format),
        }
    }
}

#[async_trait]
impl<R: AsyncBufRead + Send> TargetRead<R> for TargetReader<R> {
    async fn decode(&mut self, target: &mut Target) -> Result<()> {
        match self {
            TargetReader::Json(source, defaults) => decode_json(source, defaults, target).await,
            TargetReader::Http(source, defaults) => decode_http(source, defaults, target).await,
        }
    }
}

async fn decode_json<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    defaults: &TargetDefaults,
    target: &mut Target,
) -> Result<()> {
    let mut line = String::new();

    reader.read_line(&mut line).await?;

    if line.is_empty() {
        eyre::bail!("no targets to attack");
    }

    let t: Value = serde_json::from_str(&line)?;

    let method = match t["method"] {
        Value::String(method) => hyper::Method::from_str(&method)?,
        _ => eyre::bail!("target: valid method is missing"),
    };

    let url = match t["url"] {
        Value::String(url) => hyper::Uri::from_str(&url)?,
        _ => eyre::bail!("target: valid url is missing"),
    };

    let body = match t["body"] {
        Value::String(body) => body.as_bytes().to_vec(),
        _ => defaults.body.clone(),
    };

    Ok(())
}

async fn decode_http<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    defaults: &TargetDefaults,
    target: &mut Target,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut line = String::new();

    // Skip empty lines or comments
    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            break;
        }
        line.clear();
    }

    // Parse method and uri
    let tokens: Vec<&str> = line.splitn(2, ' ').collect();
    if tokens.len() != 2 {
        eyre::bail!("bad target: {}", line);
    }

    let method = hyper::Method::from_str(tokens[0])?.map_err(|e| {
        eyre::bail!("bad method: {}", tokens[0]);
    });

    let mut req = hyper::Request::builder().method(method).uri(tokens[1]);
    let mut body: Vec<u8> = defaults.body.clone();

    for (k, v) in defaults.headers.iter() {
        req = req.header(k, v);
    }

    // Parse headers and body
    line.clear();
    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if trimmed.starts_with('@') {
            body = tokio::fs::read(&trimmed[1..]).await?;
            break;
        }
        let tokens: Vec<&str> = line.splitn(2, ':').collect();
        if tokens.len() != 2 {
            eyre::bail!("bad header: {}", line);
        }
        req = req.header(tokens[0].trim(), tokens[1].trim());
        line.clear();
    }

    Ok(())
}
