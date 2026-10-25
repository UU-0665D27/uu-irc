//! `uu-irc` — a small, trait-based IRC stack.
//!
//! The crate is layered so every part can be replaced or driven in isolation:
//!
//! | layer | trait | default | purpose |
//! |-------|-------|---------|---------|
//! | model | [`Message`] / [`Command`] | — | parse/serialize one line |
//! | framing | [`Framer`] | [`LineFramer`] | bytes → lines, bounded |
//! | codec | [`Codec`] | [`IrcCodec`] | lines ↔ [`Message`] |
//! | transport | [`Transport`] | [`TcpConnector`]/[`MockStream`] | full-duplex bytes |
//! | connector | [`Connector`] | [`TcpConnector`] | dial a [`Target`] |
//! | client | [`Client`] | — | socket + framing + codec |
//!
//! # Fuzzing
//!
//! Reading is deliberately bidirectional: the read half ([`FrameReader`]) is
//! independent of the write half, and it accepts bytes you feed by hand via
//! [`FrameReader::feed`] or [`Client::feed`]. Nothing panics on malformed input —
//! bad lines become [`Event::Invalid`]. For a pure, socket-free entry point use
//! [`decode_all`], which is what the `fuzz/` target calls.
//!
//! ```no_run
//! # #[cfg(feature = "net")]
//! # async fn demo() -> std::io::Result<()> {
//! use uu_irc::{Command, Event, Message, Target};
//!
//! let target = Target::parse("[::1]:6667").unwrap();
//! let mut client = uu_irc::connect(&target).await?;
//! client.register("uu", "uu", "uu-irc").await?;
//! loop {
//!     match client.recv().await? {
//!         Event::Message(msg) => {
//!             if msg.command == Command::Ping {
//!                 client
//!                     .send(&Message::new(Command::Pong)
//!                         .with_param(msg.trailing().unwrap_or("")))
//!                     .await?;
//!             }
//!         }
//!         Event::Invalid(_) => {}
//!         Event::Closed => break,
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Logging
//!
//! The default `tracing` feature emits structured logs from every layer
//! (`trace!` for bytes and parser detail, `debug!` for protocol traffic,
//! `info!` for connection lifecycle, `warn!`/`error!` for recoverable and fatal
//! problems). Credentials are redacted before they reach the log. Disable the
//! feature for a dependency-free core:
//!
//! ```text
//! cargo build --no-default-features
//! ```
//!
//! # Test server
//!
//! The address used by the `connect` example defaults to the value below and can
//! be overridden with the `IRC_SERVER` environment variable.
//!
//! [`TcpConnector`]: transport::TcpConnector
//! [`MockStream`]: transport::MockStream

#[cfg(feature = "tracing")]
mod log;
#[cfg(not(feature = "tracing"))]
#[macro_use]
mod log_noop;

pub mod codec;
pub mod error;
pub mod framer;
pub mod message;

#[cfg(feature = "net")]
pub mod client;
#[cfg(feature = "net")]
pub mod transport;

pub use crate::codec::{Codec, IrcCodec, decode_all, decode_all_with};
pub use crate::error::ParseError;
pub use crate::framer::{Framer, LineFramer};
pub use crate::message::{Command, Message, Prefix, Tags};

#[cfg(feature = "net")]
pub use crate::client::{
    ChannelHandler, ChatKind, ChatMessage, Client, ClientReader, ClientWriter, DecodeError, Event,
    FrameReader, FrameWriter, SASL_TIMEOUT, connect, connect_with,
};
#[cfg(feature = "net")]
pub use crate::error::AddrError;
#[cfg(feature = "net")]
pub use crate::transport::{Connector, MockStream, Target, TcpConnector, Transport, memory_pair};

/// The default test server: the Yggdrasil interface address.
pub const DEFAULT_TEST_SERVER: &str = "[228:39cf:5792:fbd1:d5c7:a750:7ab9:4389]:6667";
