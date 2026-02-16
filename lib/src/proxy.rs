use hyper::client::connect::{Connected, Connection};
use hyper::Uri;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tower_service::Service;

/// Proxy configuration parsed from environment variables.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// HTTP proxy URL (from HTTP_PROXY / http_proxy)
    pub http_proxy: Option<Uri>,
    /// HTTPS proxy URL (from HTTPS_PROXY / https_proxy)
    pub https_proxy: Option<Uri>,
    /// Comma-separated list of hosts to bypass proxy (from NO_PROXY / no_proxy)
    pub no_proxy: Vec<String>,
    /// Custom headers to add to CONNECT requests
    pub proxy_headers: HashMap<String, String>,
}

impl ProxyConfig {
    /// Read proxy configuration from environment variables, matching Go's
    /// `http.ProxyFromEnvironment` behavior.
    pub fn from_env(proxy_headers: HashMap<String, String>) -> Self {
        let http_proxy = std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .ok()
            .and_then(|s| s.parse::<Uri>().ok());

        let https_proxy = std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .ok()
            .and_then(|s| s.parse::<Uri>().ok());

        let no_proxy = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|h| h.trim().to_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        ProxyConfig {
            http_proxy,
            https_proxy,
            no_proxy,
            proxy_headers,
        }
    }

    /// Returns the proxy URI to use for the given target URI, or None if
    /// the target should be connected directly.
    pub fn proxy_for(&self, uri: &Uri) -> Option<&Uri> {
        let host = uri.host().unwrap_or("").to_lowercase();

        // Check NO_PROXY
        for pattern in &self.no_proxy {
            if pattern == "*" {
                return None;
            }
            if host == *pattern || host.ends_with(&format!(".{}", pattern)) {
                return None;
            }
        }

        match uri.scheme_str() {
            Some("https") => self.https_proxy.as_ref(),
            _ => self.http_proxy.as_ref().or(self.https_proxy.as_ref()),
        }
    }

    /// Returns true if any proxy is configured.
    pub fn is_enabled(&self) -> bool {
        self.http_proxy.is_some() || self.https_proxy.is_some()
    }
}

/// A connector wrapper that routes connections through an HTTP proxy.
///
/// For HTTP targets: connects to the proxy host and signals `Connected::proxy(true)`
/// so hyper sends absolute-form URIs (e.g. `GET http://target/path`).
///
/// For HTTPS targets: establishes a CONNECT tunnel through the proxy, then
/// returns the raw TCP stream for the caller (typically hyper-rustls) to
/// perform TLS on top.
#[derive(Clone, Debug)]
pub struct ProxyConnector<C> {
    inner: C,
    config: ProxyConfig,
}

impl<C> ProxyConnector<C> {
    pub fn new(inner: C, config: ProxyConfig) -> Self {
        ProxyConnector { inner, config }
    }
}

/// The stream type returned by ProxyConnector.
#[derive(Debug)]
pub enum ProxyStream<S> {
    /// Direct connection (no proxy or bypassed).
    Direct(S),
    /// Connection through proxy (TCP stream to proxy).
    Proxied(TcpStream),
}

impl<S: Connection + Unpin> Connection for ProxyStream<S> {
    fn connected(&self) -> Connected {
        match self {
            ProxyStream::Direct(s) => s.connected(),
            ProxyStream::Proxied(_) => Connected::new().proxy(true),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProxyStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Direct(s) => Pin::new(s).poll_read(cx, buf),
            ProxyStream::Proxied(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ProxyStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ProxyStream::Direct(s) => Pin::new(s).poll_write(cx, buf),
            ProxyStream::Proxied(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Direct(s) => Pin::new(s).poll_flush(cx),
            ProxyStream::Proxied(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Direct(s) => Pin::new(s).poll_shutdown(cx),
            ProxyStream::Proxied(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

fn proxy_addr(proxy_uri: &Uri) -> io::Result<String> {
    let host = proxy_uri
        .host()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy URI has no host"))?;
    let port = proxy_uri
        .port_u16()
        .unwrap_or(match proxy_uri.scheme_str() {
            Some("https") => 443,
            _ => 80,
        });
    Ok(format!("{}:{}", host, port))
}

impl<C> Service<Uri> for ProxyConnector<C>
where
    C: Service<Uri> + Clone + Send + 'static,
    C::Response: Connection + AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    C::Future: Send + 'static,
{
    type Response = ProxyStream<C::Response>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let proxy_uri = self.config.proxy_for(&uri).cloned();

        match proxy_uri {
            None => {
                // No proxy: connect directly.
                let fut = self.inner.call(uri);
                Box::pin(async move {
                    let stream = fut.await.map_err(Into::into)?;
                    Ok(ProxyStream::Direct(stream))
                })
            }
            Some(proxy) => {
                let is_https = uri.scheme_str() == Some("https");
                let proxy_headers = self.config.proxy_headers.clone();

                if is_https {
                    // HTTPS: establish CONNECT tunnel through proxy.
                    let target_authority = uri
                        .authority()
                        .map(|a| a.as_str().to_string())
                        .unwrap_or_default();

                    Box::pin(async move {
                        let addr = proxy_addr(&proxy)?;
                        let mut stream = TcpStream::connect(&addr).await?;

                        // Send CONNECT request
                        let mut connect_req = format!(
                            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
                            target_authority, target_authority
                        );
                        for (key, value) in &proxy_headers {
                            connect_req.push_str(&format!("{}: {}\r\n", key, value));
                        }
                        connect_req.push_str("\r\n");

                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        stream.write_all(connect_req.as_bytes()).await?;

                        // Read CONNECT response
                        let mut buf = Vec::with_capacity(1024);
                        loop {
                            let mut byte = [0u8; 1];
                            stream.read_exact(&mut byte).await?;
                            buf.push(byte[0]);
                            if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                                break;
                            }
                            if buf.len() > 8192 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "proxy CONNECT response too large",
                                )
                                .into());
                            }
                        }

                        let response = String::from_utf8_lossy(&buf);
                        let status_line = response.lines().next().unwrap_or("");
                        if !status_line.contains("200") {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("proxy CONNECT failed: {}", status_line),
                            )
                            .into());
                        }

                        Ok(ProxyStream::Proxied(stream))
                    })
                } else {
                    // HTTP: connect to proxy, hyper sends absolute-form URI.
                    Box::pin(async move {
                        let addr = proxy_addr(&proxy)?;
                        let stream = TcpStream::connect(&addr).await?;
                        Ok(ProxyStream::Proxied(stream))
                    })
                }
            }
        }
    }
}
