//! Transport abstractions.
//!
//! Split into three traits so each concern can be swapped independently:
//!
//! * [`Transport`] — a full-duplex byte stream (blanket impl for anything that is
//!   `AsyncRead + AsyncWrite + Unpin + Send`).
//! * [`Connector`] — a way to obtain a transport for a [`Target`].
//! * [`MockStream`] — an in-memory duplex transport for tests and fuzzing where
//!   you control exactly which bytes arrive and can inspect what was written.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::AddrError;
#[cfg(feature = "tracing")]
use crate::log::{debug, error, info, trace};

/// A full-duplex byte transport.
///
/// Any `AsyncRead + AsyncWrite + Unpin + Send` type implements it, so
/// [`tokio::net::TcpStream`], [`tokio::io::DuplexStream`] and [`MockStream`] all
/// work without extra glue.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> Transport for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A host/port pair. Supports `host:port`, `[ipv6]:port` and a bare host
/// (which defaults to port 6667).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host name or IP literal (without brackets).
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Target {
    /// The default IRC port.
    pub const DEFAULT_PORT: u16 = 6667;

    /// Build a target.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Parse `host[:port]`.
    pub fn parse(s: &str) -> Result<Self, AddrError> {
        trace!(input = s, "parsing target address");
        let s = s.trim();
        if s.is_empty() {
            debug!("target address is empty");
            return Err(AddrError::MissingHost);
        }
        if let Some(rest) = s.strip_prefix('[') {
            let (host, tail) = rest.split_once(']').ok_or(AddrError::MissingHost)?;
            if host.is_empty() {
                debug!("target address has an empty host");
                return Err(AddrError::MissingHost);
            }
            let port = match tail.strip_prefix(':') {
                Some(p) => parse_port(p)?,
                None => Self::DEFAULT_PORT,
            };
            trace!(host, port, "parsed target address");
            return Ok(Self::new(host, port));
        }
        match s.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => {
                let port = parse_port(port)?;
                trace!(host, port, "parsed target address");
                Ok(Self::new(host, port))
            }
            Some(_) | None => {
                if s.is_empty() {
                    Err(AddrError::MissingHost)
                } else {
                    trace!(host = s, port = Self::DEFAULT_PORT, "parsed target address");
                    Ok(Self::new(s, Self::DEFAULT_PORT))
                }
            }
        }
    }
}

fn parse_port(p: &str) -> Result<u16, AddrError> {
    match p.parse::<u16>() {
        Ok(port) => {
            trace!(port, "parsed port");
            Ok(port)
        }
        Err(_) => {
            debug!(port = p, "invalid port");
            Err(AddrError::InvalidPort(p.to_string()))
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl std::str::FromStr for Target {
    type Err = AddrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Target::parse(s)
    }
}

/// Obtains a [`Transport`] for a [`Target`].
pub trait Connector {
    /// The transport produced by this connector.
    type Stream: Transport;
    /// The connect error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Dial the target, returning a connected, full-duplex transport.
    fn connect(
        &self,
        target: &Target,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Self::Error>> + Send;
}

/// A plain TCP connector.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpConnector;

impl Connector for TcpConnector {
    type Stream = tokio::net::TcpStream;
    type Error = io::Error;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, Self::Error> {
        debug!(%target, "opening TCP connection");
        match tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await {
            Ok(stream) => {
                if let Ok(peer) = stream.peer_addr() {
                    info!(%target, %peer, "TCP connection established");
                } else {
                    info!(%target, "TCP connection established");
                }
                Ok(stream)
            }
            Err(error) => {
                error!(%target, %error, "TCP connection failed");
                Err(error)
            }
        }
    }
}

/// Create a connected, in-memory duplex pair backed by tokio.
///
/// Whatever is written into one half can be read from the other, which is how
/// integration tests stand in for the real server.
pub fn memory_pair(capacity: usize) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    debug!(capacity, "creating in-memory transport pair");
    tokio::io::duplex(capacity)
}

/// An in-memory transport for tests and fuzzing.
///
/// Inbound bytes are supplied explicitly with [`MockStream::push_inbound`]; the
/// bytes written by the code under test are captured and returned by
/// [`MockStream::take_written`]. Nothing here touches the network, so a fuzzer
/// can drive the whole client deterministically.
#[derive(Debug, Default)]
pub struct MockStream {
    inbound: VecDeque<u8>,
    written: Vec<u8>,
    inbound_closed: bool,
    shutdown: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl MockStream {
    /// An empty mock stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue bytes that the code under test will read.
    pub fn push_inbound(&mut self, data: &[u8]) {
        trace!(len = data.len(), "mock stream: inbound bytes queued");
        self.inbound.extend(data.iter().copied());
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }

    /// Signal end-of-stream to the reader.
    pub fn close_inbound(&mut self) {
        debug!("mock stream: inbound closed");
        self.inbound_closed = true;
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }

    /// All bytes written so far.
    pub fn written(&self) -> &[u8] {
        &self.written
    }

    /// Take the bytes written so far, clearing the buffer.
    pub fn take_written(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.written)
    }

    /// Whether the writer has shut the stream down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Number of inbound bytes still buffered.
    pub fn pending_inbound(&self) -> usize {
        self.inbound.len()
    }
}

impl AsyncRead for MockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.inbound.is_empty() {
            if self.inbound_closed {
                trace!("mock stream: read hit end of stream");
                return Poll::Ready(Ok(()));
            }
            self.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.remaining().min(self.inbound.len());
        for _ in 0..n {
            let byte = self.inbound.pop_front().expect("checked len");
            buf.put_slice(&[byte]);
        }
        trace!(n, "mock stream: inbound bytes read");
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        trace!(len = buf.len(), "mock stream: bytes written");
        self.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        debug!("mock stream: writer shut down");
        self.shutdown = true;
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addresses() {
        let t = Target::parse("irc.example.org").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("irc.example.org", 6667));

        let t = Target::parse("irc.example.org:7000").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("irc.example.org", 7000));

        let t = Target::parse("[::1]:6667").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", 6667));

        let t = Target::parse("[2001:db8::1]").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("2001:db8::1", 6667));

        assert!(Target::parse("host:notaport").is_err());
        assert!(Target::parse("").is_err());
    }

    #[test]
    fn display_round_trips() {
        for s in ["irc.example.org:6667", "[::1]:7000", "127.0.0.1:6667"] {
            let t = Target::parse(s).unwrap();
            assert_eq!(t.to_string(), s);
            assert_eq!(Target::parse(&t.to_string()).unwrap(), t);
        }
    }
}
