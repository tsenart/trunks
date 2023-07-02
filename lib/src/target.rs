use async_trait::async_trait;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Error as IoError;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Target {
    pub method: String,
    pub url: String,
    pub body: Option<String>,
    pub header: Option<HashMap<String, Vec<String>>>,
}

impl Target {
    pub fn new(
        method: String,
        url: String,
        body: Option<String>,
        header: Option<HashMap<String, Vec<String>>>,
    ) -> Self {
        Self {
            method,
            url,
            body,
            header,
        }
    }
}

impl Target {
    pub fn request(&self) -> Result<reqwest::Request> {
        let url = reqwest::Url::parse(&self.url)?;
        let method = reqwest::Method::from_str(&self.method)?;
        let mut req = reqwest::Request::new(method, url);

        if let Some(headers) = &self.header {
            let headers_map = req.headers_mut();
            for (k, v) in headers.iter() {
                for header_value in v {
                    let header_name = reqwest::header::HeaderName::from_bytes(k.as_bytes())?;
                    let header_value = reqwest::header::HeaderValue::from_str(header_value)?;
                    headers_map.insert(header_name, header_value);
                }
            }
        }

        // if let Some(body) = &self.body {
        //     req.body_mut()
        //         .and_then(|b| b.as_bytes().and_then(|b2| Some(())));
        // }

        Ok(req)
    }
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

#[derive(Debug, Clone)]
pub enum TargetReader<R: AsyncBufRead> {
    Json(Pin<Box<R>>),
    Http(Pin<Box<R>>),
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
            TargetReader::Json(source) => decode_json(source, target).await,
            TargetReader::Http(source) => decode_http(source, target).await,
        }
    }
}

async fn decode_json<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    target: &mut Target,
) -> Result<()> {
    let mut line = String::new();

    reader.read_line(&mut line).await?;

    if line.is_empty() {
        return Err(IoError::new(std::io::ErrorKind::Other, "no targets to attack").into());
    }

    let t: Target = serde_json::from_str(&line)?;

    if t.method.is_empty() {
        return Err(IoError::new(
            std::io::ErrorKind::Other,
            "target: required method is missing",
        )
        .into());
    }

    if t.url.is_empty() {
        return Err(
            IoError::new(std::io::ErrorKind::Other, "target: required url is missing").into(),
        );
    }

    if t.body.is_none() && target.body.is_some() {
        target.body = t.body;
    }

    if target.header.is_none() {
        target.header = t.header;
    }

    Ok(())
}

pub async fn decode_http<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    target: &mut Target,
) -> Result<()> {
    let mut line = String::new();

    reader.read_line(&mut line).await?;

    if line.is_empty() {
        return Err(IoError::new(std::io::ErrorKind::Other, "no targets to attack").into());
    }

    let tokens: Vec<&str> = line.trim().split(' ').collect();

    if tokens.len() != 2 {
        return Err(IoError::new(
            std::io::ErrorKind::Other,
            "invalid request: format should be [METHOD] [URL]",
        )
        .into());
    }

    target.method = tokens[0].to_string();
    target.url = tokens[1].to_string();

    // Handle HTTP Headers
    let mut headers = HashMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await?;

        if line.trim().is_empty() {
            break;
        }

        let header_tokens: Vec<&str> = line.splitn(2, ":").collect();

        if header_tokens.len() != 2 {
            return Err(IoError::new(
                std::io::ErrorKind::Other,
                "invalid header: format should be [Key]: [Value]",
            )
            .into());
        }

        let header_name = header_tokens[0].trim().to_string();
        let header_value = header_tokens[1].trim().to_string();

        headers
            .entry(header_name)
            .or_insert(vec![])
            .push(header_value);
    }

    if headers.is_empty() {
        target.header = Some(headers);
    }

    // Handle HTTP Body
    line.clear();
    reader.read_line(&mut line).await?;
    let body_line = line.trim().to_string();

    if !body_line.is_empty() {
        if body_line.starts_with('@') {
            // The line starts with @, so treat the rest of the line as a filename to read from
            let file_path = body_line.trim_start_matches('@');
            match fs::read_to_string(file_path) {
                Ok(file_content) => target.body = Some(file_content),
                Err(e) => return Err(e.into()),
            }
        } else {
            // If the line does not start with @, just use it as the body
            target.body = Some(body_line);
        }
    }

    Ok(())
}
