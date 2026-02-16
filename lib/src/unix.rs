use hyper::client::connect::{Connected, Connection};
use hyper::Uri;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower_service::Service;

/// A hyper connector that routes all requests through a Unix domain socket,
/// regardless of the URI's host. Mirrors vegeta's approach where the socket
/// path is fixed and the URI host is ignored for dialing.
#[derive(Clone, Debug)]
pub struct UnixConnector {
    path: PathBuf,
}

impl UnixConnector {
    pub fn new(path: impl AsRef<Path>) -> Self {
        UnixConnector {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl Service<Uri> for UnixConnector {
    type Response = UnixStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let path = self.path.clone();
        Box::pin(async move {
            let stream = tokio::net::UnixStream::connect(&path).await?;
            Ok(UnixStream { inner: stream })
        })
    }
}

/// Wrapper around `tokio::net::UnixStream` that implements hyper's `Connection` trait.
#[derive(Debug)]
pub struct UnixStream {
    inner: tokio::net::UnixStream,
}

impl Connection for UnixStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AsyncRead for UnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for UnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
