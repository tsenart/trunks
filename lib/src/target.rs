use async_trait::async_trait;
use eyre::Result;
use hyper::body::Bytes;
use hyper::header::HeaderValue;
use hyper::http::HeaderName;
use hyper::{HeaderMap, Method, Uri};
use serde::Deserialize;
use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

#[derive(Debug, Default, Clone)]
pub struct Target {
    pub method: Method,
    pub url: Uri,
    pub headers: HeaderMap<HeaderValue>,
    pub body: Bytes,
}

#[async_trait]
pub trait TargetRead<R: AsyncBufRead> {
    async fn decode(&mut self) -> Result<Arc<Target>>;
}

#[derive(Default, Debug)]
pub enum Targets<R: AsyncBufRead + Send> {
    #[default]
    None,
    Static {
        pos: Arc<AtomicUsize>,
        targets: Vec<Arc<Target>>,
    },
    Lazy(TargetReader<R>),
}

impl<R: AsyncBufRead + Send> From<Vec<Arc<Target>>> for Targets<R> {
    fn from(targets: Vec<Arc<Target>>) -> Self {
        Self::Static {
            pos: Arc::new(AtomicUsize::new(0)),
            targets,
        }
    }
}

#[async_trait]
impl<R: AsyncBufRead + Send> TargetRead<R> for Targets<R> {
    async fn decode(&mut self) -> Result<Arc<Target>> {
        match self {
            Targets::None => eyre::bail!("no targets"),
            Targets::Static { pos, targets } => {
                if targets.is_empty() {
                    eyre::bail!("no targets")
                }
                Ok(targets[pos.fetch_add(1, Ordering::SeqCst) % targets.len()].clone())
            }
            Targets::Lazy(reader) => reader.decode().await,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TargetDefaults {
    // body will be used if none is read from input
    pub body: Option<Bytes>,
    // headers will be over-written by the headers read from input
    pub headers: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Clone)]
pub struct TargetReaderInner<R: AsyncBufRead> {
    input: Pin<Box<R>>,
    defaults: TargetDefaults,
}

impl<R: AsyncBufRead> TargetReaderInner<R> {
    pub fn new(input: R, defaults: TargetDefaults) -> Self {
        TargetReaderInner {
            input: Box::pin(input),
            defaults,
        }
    }
}

#[derive(Debug, Clone)]
pub enum TargetReader<R: AsyncBufRead> {
    Json(TargetReaderInner<R>),
    Http(TargetReaderInner<R>),
}

impl<R: AsyncBufRead> TargetReader<R> {
    pub fn new(format: &str, input: R, defaults: TargetDefaults) -> Result<Self> {
        let tr = TargetReaderInner::new(input, defaults);
        match format {
            "json" => Ok(TargetReader::Json(tr)),
            "http" => Ok(TargetReader::Http(tr)),
            _ => eyre::bail!("invalid target format: {}", format),
        }
    }
}

#[async_trait]
impl<R: AsyncBufRead + Send> TargetRead<R> for TargetReader<R> {
    async fn decode(&mut self) -> Result<Arc<Target>> {
        match self {
            TargetReader::Json(tr) => decode_json(&mut tr.input, &tr.defaults).await,
            TargetReader::Http(tr) => decode_http(&mut tr.input, &tr.defaults).await,
        }
    }
}

async fn decode_json<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    defaults: &TargetDefaults,
) -> eyre::Result<Arc<Target>> {
    let mut line = String::new();

    reader.read_line(&mut line).await?;

    if line.is_empty() {
        eyre::bail!("no targets to attack");
    }

    #[derive(Deserialize)]
    struct JSONTarget {
        method: String,
        url: String,
        headers: HashMap<String, Vec<String>>,
        body: String,
    }

    let v: JSONTarget = serde_json::from_str(&line)?;

    let method = Method::from_str(&v.method)?;
    let url = Uri::from_str(&v.url)?;
    let mut headers = HeaderMap::new();

    if let Some(default_headers) = &defaults.headers {
        for (k, vs) in default_headers {
            for v in vs {
                headers.append(HeaderName::from_str(k)?, HeaderValue::from_str(v)?);
            }
        }
    }

    for (k, vs) in &v.headers {
        for v in vs {
            headers.append(HeaderName::from_str(k)?, HeaderValue::from_str(v)?);
        }
    }

    let body = if v.body.is_empty() {
        if let Some(body) = &defaults.body {
            body.clone()
        } else {
            Bytes::new()
        }
    } else {
        base64_simd::STANDARD
            .decode_to_vec(v.body)
            .map_err(|e| eyre::eyre!(e))?
            .into()
    };

    Ok(Arc::new(Target {
        method,
        url,
        headers,
        body,
    }))
}

async fn decode_http<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    defaults: &TargetDefaults,
) -> eyre::Result<Arc<Target>> {
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

    let method = Method::from_str(tokens[0].trim())?;
    let url = Uri::from_str(tokens[1].trim())?;
    let mut headers = HeaderMap::new();
    let mut body = if let Some(body) = &defaults.body {
        body.clone()
    } else {
        Bytes::new()
    };

    if let Some(default_headers) = &defaults.headers {
        for (k, vs) in default_headers {
            for v in vs {
                headers.append(HeaderName::from_str(k)?, HeaderValue::from_str(v)?);
            }
        }
    }

    // Parse headers and body
    line.clear();
    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(body_path) = trimmed.strip_prefix('@') {
            body = Bytes::from(tokio::fs::read(body_path).await?);
            break;
        }
        let tokens: Vec<&str> = line.splitn(2, ':').collect();
        if tokens.len() != 2 {
            eyre::bail!("bad header: {}", line);
        }
        headers.append(
            HeaderName::from_str(tokens[0].trim())?,
            HeaderValue::from_str(tokens[1].trim())?,
        );
        line.clear();
    }

    Ok(Arc::new(Target {
        method,
        url,
        headers,
        body,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn http_format_method_and_url() {
        let input = b"GET http://example.com/api\n\n" as &[u8];
        let reader = BufReader::new(input);
        let mut tr = TargetReader::new("http", reader, TargetDefaults::default()).unwrap();
        let target = tr.decode().await.unwrap();
        assert_eq!(target.method, Method::GET);
        assert_eq!(target.url.host().unwrap(), "example.com");
        assert_eq!(target.url.path(), "/api");
    }

    #[tokio::test]
    async fn http_format_with_headers() {
        let input = b"POST http://example.com/\nContent-Type: application/json\nX-Custom: value\n\n"
            as &[u8];
        let reader = BufReader::new(input);
        let mut tr = TargetReader::new("http", reader, TargetDefaults::default()).unwrap();
        let target = tr.decode().await.unwrap();
        assert_eq!(target.method, Method::POST);
        assert!(target.headers.contains_key("content-type"));
        assert!(target.headers.contains_key("x-custom"));
    }

    #[tokio::test]
    async fn json_format_parsing() {
        let input = br#"{"method":"PUT","url":"http://example.com/resource","headers":{"Authorization":["Bearer token"]},"body":""}"#;
        let mut full = input.to_vec();
        full.push(b'\n');
        let reader = BufReader::new(full.as_slice());
        let mut tr = TargetReader::new("json", reader, TargetDefaults::default()).unwrap();
        let target = tr.decode().await.unwrap();
        assert_eq!(target.method, Method::PUT);
        assert!(target.url.to_string().contains("resource"));
        assert!(target.headers.contains_key("authorization"));
    }

    #[tokio::test]
    async fn static_targets_round_robin() {
        let t1 = Arc::new(Target {
            method: Method::GET,
            url: Uri::from_static("http://a/"),
            ..Default::default()
        });
        let t2 = Arc::new(Target {
            method: Method::GET,
            url: Uri::from_static("http://b/"),
            ..Default::default()
        });
        let t3 = Arc::new(Target {
            method: Method::GET,
            url: Uri::from_static("http://c/"),
            ..Default::default()
        });
        let mut targets: Targets<&[u8]> = Targets::from(vec![t1, t2, t3]);

        let mut urls = Vec::new();
        for _ in 0..6 {
            let t = targets.decode().await.unwrap();
            urls.push(t.url.to_string());
        }
        assert_eq!(
            urls,
            vec![
                "http://a/",
                "http://b/",
                "http://c/",
                "http://a/",
                "http://b/",
                "http://c/"
            ]
        );
    }

    #[tokio::test]
    async fn empty_targets_error() {
        let mut targets: Targets<&[u8]> = Targets::None;
        assert!(targets.decode().await.is_err());
    }

    #[tokio::test]
    async fn empty_static_targets_error() {
        let mut targets: Targets<&[u8]> = Targets::from(vec![]);
        assert!(targets.decode().await.is_err());
    }

    #[test]
    fn invalid_format_error() {
        let input = b"" as &[u8];
        let reader = BufReader::new(input);
        assert!(TargetReader::new("xml", reader, TargetDefaults::default()).is_err());
    }

    #[tokio::test]
    async fn http_format_skips_comments() {
        let input = b"# comment line\nGET http://example.com/\n\n" as &[u8];
        let reader = BufReader::new(input);
        let mut tr = TargetReader::new("http", reader, TargetDefaults::default()).unwrap();
        let target = tr.decode().await.unwrap();
        assert_eq!(target.method, Method::GET);
    }
}
