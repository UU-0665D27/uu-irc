//! The async client: a socket plus framing plus codec.
//!
//! Reading is fully bidirectional in the sense that the reader half is an
//! independent object you can drive on its own task, and — crucially for
//! fuzzing — you can inject arbitrary bytes into the reader with
//! [`FrameReader::feed`] instead of (or in addition to) pulling them off the
//! socket.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::{Codec, IrcCodec};
use crate::error::ParseError;
use crate::framer::{Framer, LineFramer};
#[cfg(feature = "tracing")]
use crate::log::{debug, error, info, trace, warn};
use crate::message::{Command, Message};
use crate::transport::{Connector, Target, TcpConnector, Transport};

/// A line that failed to decode, kept together with its raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    /// The offending line (terminator stripped).
    pub raw: Vec<u8>,
    /// Why it failed.
    pub error: ParseError,
}

/// Something produced by the reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A decoded message.
    Message(Message),
    /// A malformed line. The connection stays open.
    Invalid(DecodeError),
    /// The peer closed the stream (or the mock input was closed).
    Closed,
}

impl Event {
    /// Consume the event, returning the message if there is one.
    pub fn into_message(self) -> Option<Message> {
        match self {
            Event::Message(m) => Some(m),
            _ => None,
        }
    }
}

/// The kind of a [`ChatMessage`] routed to a channel handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatKind {
    /// A regular channel message (`PRIVMSG`).
    Privmsg,
    /// A notice (`NOTICE`).
    Notice,
    /// A tag-only message (`TAGMSG`, IRCv3).
    Tagmsg,
    /// Someone joined the channel.
    Join,
    /// Someone left the channel.
    Part,
    /// The channel topic was changed or shown.
    Topic,
    /// Channel or user modes changed.
    Mode,
    /// Someone was kicked.
    Kick,
    /// Someone was invited.
    Invite,
    /// A numeric reply that happened to be addressed to the channel.
    Numeric(u16),
    /// The server reported an error.
    Error,
    /// Any other command.
    Other(String),
}

/// A high-level, structured view of a message addressed to a channel.
///
/// Channel handlers registered with [`Client::join`] receive this instead of the
/// raw protocol [`Message`]: the useful parts (channel, sender, kind, text) are
/// typed fields, and [`ChatMessage::raw`] keeps the original message for anything
/// else. Build replies with [`ChatMessage::reply`] / [`ChatMessage::notice`].
///
/// ```no_run
/// # async fn demo(client: &mut uu_irc::Client<tokio::net::TcpStream>) -> std::io::Result<()> {
/// use uu_irc::ChatKind;
///
/// client
///     .join("#uu", |chat| {
///         if chat.kind == ChatKind::Privmsg && chat.text() == Some("!ping") {
///             Some(chat.reply("pong"))
///         } else {
///             None
///         }
///     })
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    /// The target channel, exactly as it appeared on the wire.
    pub channel: String,
    /// Nickname of the sender (`None` for server-originated messages).
    pub sender: Option<String>,
    /// What kind of event this is.
    pub kind: ChatKind,
    /// Human-readable payload: message text, part/topic reason, kick reason, ...
    pub text: Option<String>,
    /// The decoded protocol message this view was built from.
    pub raw: Message,
}

impl ChatMessage {
    /// Build a structured view from a decoded message addressed to `channel`.
    pub fn from_message(msg: &Message) -> Option<Self> {
        let channel = msg.params.first()?.clone();
        let kind = match &msg.command {
            Command::Privmsg => ChatKind::Privmsg,
            Command::Notice => ChatKind::Notice,
            Command::Tagmsg => ChatKind::Tagmsg,
            Command::Join => ChatKind::Join,
            Command::Part => ChatKind::Part,
            Command::Topic => ChatKind::Topic,
            Command::Mode => ChatKind::Mode,
            Command::Kick => ChatKind::Kick,
            Command::Invite => ChatKind::Invite,
            Command::Numeric(code) => ChatKind::Numeric(*code),
            Command::Error => ChatKind::Error,
            other => ChatKind::Other(other.to_string()),
        };
        let text = match kind {
            ChatKind::Privmsg
            | ChatKind::Notice
            | ChatKind::Tagmsg
            | ChatKind::Part
            | ChatKind::Topic => msg.params.get(1).cloned(),
            ChatKind::Kick => msg.params.get(2).cloned(),
            _ => None,
        };
        Some(Self {
            channel,
            sender: msg
                .prefix
                .as_ref()
                .filter(|prefix| !prefix.is_server())
                .map(|prefix| prefix.name.clone()),
            kind,
            text,
            raw: msg.clone(),
        })
    }

    /// The message text / reason, if this kind carries one.
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// The sender nickname, if any.
    pub fn sender(&self) -> Option<&str> {
        self.sender.as_deref()
    }

    /// Whether the message was sent by `nick` (case-insensitive).
    pub fn is_from(&self, nick: &str) -> bool {
        self.sender
            .as_deref()
            .is_some_and(|sender| sender.eq_ignore_ascii_case(nick))
    }

    /// Whether this is a regular channel message.
    pub fn is_privmsg(&self) -> bool {
        self.kind == ChatKind::Privmsg
    }

    /// Build a channel reply (`PRIVMSG <channel> :<text>`).
    pub fn reply(&self, text: impl Into<String>) -> Message {
        Message::new(Command::Privmsg)
            .with_param(self.channel.clone())
            .with_trailing(text)
    }

    /// Build a channel notice (`NOTICE <channel> :<text>`).
    pub fn notice(&self, text: impl Into<String>) -> Message {
        Message::new(Command::Notice)
            .with_param(self.channel.clone())
            .with_trailing(text)
    }
}

fn decode<C: Codec>(codec: &C, line: Vec<u8>) -> Event {
    match codec.decode(&line) {
        Ok(message) => Event::Message(message),
        Err(error) => Event::Invalid(DecodeError { raw: line, error }),
    }
}

/// Formats a message for the log with credentials masked.
///
/// `PASS` and `AUTHENTICATE` parameters, plus `IDENTIFY`/`REGISTER` passwords
/// sent to services, are replaced with `***`. `Display` is only called when a
/// log event is enabled.
struct Redacted<'a>(&'a Message);

impl fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut msg = self.0.clone();
        let mut changed = false;

        if matches!(msg.command, Command::Pass | Command::Authenticate) {
            for param in &mut msg.params {
                *param = "***".to_string();
                changed = true;
            }
        } else if msg.command == Command::Privmsg {
            // Services are addressed by many names (NickServ, Q, ...), so match
            // on the command in the trailing parameter instead of the target.
            if let Some(trailing) = msg.params.last_mut() {
                let upper = trailing.to_ascii_uppercase();
                for verb in ["IDENTIFY", "REGISTER"] {
                    if upper.starts_with(verb) {
                        *trailing = format!("{verb} ***");
                        changed = true;
                        break;
                    }
                }
            }
        }

        if changed {
            trace!("redacted credentials in logged message");
        }
        f.write_str(&msg.to_string_line())
    }
}

/// How long [`Client::sasl_login`] waits for each server reply.
pub const SASL_TIMEOUT: Duration = Duration::from_secs(30);

/// A per-channel callback installed by [`Client::join`].
///
/// It is called for every decoded message whose first parameter names the
/// channel. The callback may return one message, which the client sends back
/// automatically (see [`Client::join`] for an example).
pub type ChannelHandler = Box<dyn FnMut(&ChatMessage) -> Option<Message> + Send>;

/// `ChannelHandler` is not `Debug`, so wrap it to keep `Client` printable.
struct Handler {
    callback: ChannelHandler,
}

impl fmt::Debug for Handler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelHandler(..)")
    }
}

/// IRC channel names are case-insensitive. This is the ASCII part of RFC 1459
/// casemapping; the `{}|^` ↔ `[]\~` aliases are not folded.
fn channel_key(channel: &str) -> String {
    channel.to_ascii_lowercase()
}

fn is_cap_subcommand(msg: &Message, subcommand: &str) -> bool {
    msg.command == Command::Cap
        && msg
            .params
            .iter()
            .skip(1)
            .any(|p| p.eq_ignore_ascii_case(subcommand))
}

/// Numerics that finish a SASL exchange (success or failure).
fn is_sasl_result(msg: &Message) -> bool {
    matches!(msg.command.numeric(), Some(902..=907))
}

fn sasl_result(code: u16) -> io::Result<()> {
    match code {
        900 | 903 => Ok(()),
        902 => Err(io::Error::other("SASL: nick or account is locked")),
        904 => Err(io::Error::other("SASL: authentication failed")),
        905 => Err(io::Error::other("SASL: message too long")),
        906 => Err(io::Error::other("SASL: authentication aborted")),
        907 => Err(io::Error::other("SASL: already authenticated")),
        other => Err(io::Error::other(format!(
            "SASL: unexpected numeric {other:03}"
        ))),
    }
}

/// Standard base64, so SASL PLAIN needs no extra dependency.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// The read half of the stack.
///
/// Owns a framer, so it can be moved to its own task after
/// [`Client::split`](Client::split).
#[derive(Debug)]
pub struct FrameReader<R, C = IrcCodec, F = LineFramer> {
    io: R,
    codec: C,
    framer: F,
    eof_seen: bool,
}

impl<R, C, F> FrameReader<R, C, F>
where
    R: AsyncRead + Unpin,
    C: Codec,
    F: Framer,
{
    /// Build a reader over any async byte source.
    pub fn new(io: R, codec: C, framer: F) -> Self {
        Self {
            io,
            codec,
            framer,
            eof_seen: false,
        }
    }

    /// Inject bytes directly, bypassing the socket. Returns every complete
    /// message (or error) that became available. This is the fuzzing entry
    /// point: bytes in, events out, no I/O.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Event> {
        trace!(len = bytes.len(), "feeding bytes into the reader");
        self.framer.push(bytes);
        let events = self.drain_ready(false);
        debug!(events = events.len(), "feed produced events");
        events
    }

    /// Decode any buffered complete lines without touching the socket.
    pub fn drain(&mut self) -> Vec<Event> {
        let events = self.drain_ready(false);
        trace!(events = events.len(), "drained buffered lines");
        events
    }

    /// Flush and decode a trailing partial line (call at end of input). Returns
    /// zero or one event.
    pub fn finish(&mut self) -> Vec<Event> {
        match self.framer.take_remaining() {
            Some(line) => {
                trace!(len = line.len(), "finishing reader with a partial line");
                vec![decode(&self.codec, line)]
            }
            None => {
                trace!("finishing reader with no buffered bytes");
                Vec::new()
            }
        }
    }

    fn drain_ready(&mut self, include_partial: bool) -> Vec<Event> {
        let mut out = Vec::new();
        while let Some(line) = self.framer.next_line() {
            out.push(decode(&self.codec, line));
        }
        if include_partial && let Some(line) = self.framer.take_remaining() {
            out.push(decode(&self.codec, line));
        }
        out
    }

    /// Read one event from the socket, decoding buffered data first.
    pub async fn recv(&mut self) -> io::Result<Event> {
        loop {
            if let Some(line) = self.framer.next_line() {
                trace!(len = line.len(), "reader: buffered line available");
                return Ok(decode(&self.codec, line));
            }
            if self.eof_seen {
                // Flush a final unterminated line, if any.
                if let Some(line) = self.framer.take_remaining() {
                    debug!(
                        len = line.len(),
                        "reader: flushing unterminated line at EOF"
                    );
                    return Ok(decode(&self.codec, line));
                }
                info!("reader: peer closed the connection");
                return Ok(Event::Closed);
            }

            let mut buf = [0u8; 8192];
            let n = match self.io.read(&mut buf).await {
                Ok(n) => n,
                Err(error) => {
                    error!(%error, "reader: socket read failed");
                    return Err(error);
                }
            };
            if n == 0 {
                self.eof_seen = true;
                debug!("reader: end of stream reached");
            } else {
                trace!(n, "reader: bytes read from socket");
                self.framer.push(&buf[..n]);
            }
        }
    }

    /// The underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.io
    }

    /// Number of buffered bytes in the current partial line.
    pub fn buffered(&self) -> usize {
        self.framer.buffered()
    }

    /// Mutable access to the codec.
    pub fn codec(&self) -> &C {
        &self.codec
    }
}

/// The write half of the stack.
#[derive(Debug)]
pub struct FrameWriter<W, C = IrcCodec> {
    io: W,
    codec: C,
}

impl<W, C> FrameWriter<W, C>
where
    W: AsyncWrite + Unpin,
    C: Codec,
{
    /// Build a writer over any async byte sink.
    pub fn new(io: W, codec: C) -> Self {
        Self { io, codec }
    }

    /// Encode and send a message.
    pub async fn send(&mut self, msg: &Message) -> io::Result<()> {
        trace!("writer: encoding message");
        let buf = self.codec.encode(msg);
        debug!(message = %Redacted(msg), len = buf.len(), "writer: sending message");
        if let Err(error) = self.io.write_all(&buf).await {
            error!(%error, "writer: write failed");
            return Err(error);
        }
        if let Err(error) = self.io.flush().await {
            error!(%error, "writer: flush failed");
            return Err(error);
        }
        trace!(len = buf.len(), "writer: message sent");
        Ok(())
    }

    /// Send arbitrary bytes verbatim. Handy when fuzzing the server: you are not
    /// limited to well-formed [`Message`] values.
    pub async fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        trace!(
            len = bytes.len(),
            data = %String::from_utf8_lossy(bytes),
            "writer: sending raw bytes"
        );
        if let Err(error) = self.io.write_all(bytes).await {
            error!(%error, "writer: raw write failed");
            return Err(error);
        }
        if let Err(error) = self.io.flush().await {
            error!(%error, "writer: raw flush failed");
            return Err(error);
        }
        Ok(())
    }

    /// Flush buffered writes.
    pub async fn flush(&mut self) -> io::Result<()> {
        trace!("writer: flushing");
        self.io.flush().await
    }

    /// The underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.io
    }
}

/// The read half produced by [`Client::split`].
pub type ClientReader<T, C = IrcCodec, F = LineFramer> = FrameReader<tokio::io::ReadHalf<T>, C, F>;

/// The write half produced by [`Client::split`].
pub type ClientWriter<T, C = IrcCodec> = FrameWriter<tokio::io::WriteHalf<T>, C>;

/// A connected IRC client.
#[derive(Debug)]
pub struct Client<T, C = IrcCodec, F = LineFramer>
where
    T: Transport,
{
    reader: FrameReader<T, C, F>,
    codec: C,
    buf: Vec<u8>,
    channels: HashMap<String, Handler>,
}

impl<T> Client<T, IrcCodec, LineFramer>
where
    T: Transport,
{
    /// Wrap an already-connected transport with the default codec and framer.
    pub fn new(io: T) -> Self {
        Self::with(io, IrcCodec, LineFramer::default())
    }
}

impl<T, C, F> Client<T, C, F>
where
    T: Transport,
    C: Codec,
    F: Framer,
{
    /// Wrap a transport with a custom codec and framer.
    pub fn with(io: T, codec: C, framer: F) -> Self {
        trace!("client: wrapping transport");
        Self {
            reader: FrameReader::new(io, codec.clone(), framer),
            codec,
            buf: Vec::new(),
            channels: HashMap::new(),
        }
    }

    /// Read the next event from the server.
    ///
    /// If the event is a message addressed to a channel registered with
    /// [`Client::join`], the channel handler runs before this returns, and any
    /// reply it produces is sent automatically.
    pub async fn recv(&mut self) -> io::Result<Event> {
        trace!("client: waiting for the next event");
        let event = self.reader.recv().await?;
        match &event {
            Event::Message(msg) => {
                debug!(message = %Redacted(msg), "client: received message");
                if let Some(reply) = self.dispatch(msg) {
                    debug!(
                        message = %Redacted(&reply),
                        "client: channel handler produced a reply"
                    );
                    self.send(&reply).await?;
                }
            }
            Event::Invalid(err) => warn!(
                raw = %String::from_utf8_lossy(&err.raw),
                error = %err.error,
                "client: dropping malformed line"
            ),
            Event::Closed => info!("client: connection closed"),
        }
        Ok(event)
    }

    /// Encode and send a message.
    pub async fn send(&mut self, msg: &Message) -> io::Result<()> {
        trace!("client: encoding outgoing message");
        self.buf.clear();
        self.codec.encode_into(msg, &mut self.buf);
        debug!(
            message = %Redacted(msg),
            len = self.buf.len(),
            "client: sending message"
        );
        if let Err(error) = self.reader.io.write_all(&self.buf).await {
            error!(%error, "client: write failed");
            return Err(error);
        }
        if let Err(error) = self.reader.io.flush().await {
            error!(%error, "client: flush failed");
            return Err(error);
        }
        Ok(())
    }

    /// Send raw bytes verbatim (fuzzing / protocol experiments).
    pub async fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        trace!(
            len = bytes.len(),
            data = %String::from_utf8_lossy(bytes),
            "client: sending raw bytes"
        );
        if let Err(error) = self.reader.io.write_all(bytes).await {
            error!(%error, "client: raw write failed");
            return Err(error);
        }
        if let Err(error) = self.reader.io.flush().await {
            error!(%error, "client: raw flush failed");
            return Err(error);
        }
        Ok(())
    }

    /// Inject bytes into the reader without I/O, returning decoded events.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Event> {
        self.reader.feed(bytes)
    }

    /// Flush a trailing partial line from the reader (end-of-input).
    pub fn finish(&mut self) -> Vec<Event> {
        self.reader.finish()
    }

    /// Perform minimal registration: `NICK` followed by `USER`.
    pub async fn register(&mut self, nick: &str, user: &str, realname: &str) -> io::Result<()> {
        info!(nick, user, "client: registering");
        self.send(&Message::new(Command::Nick).with_param(nick))
            .await?;
        self.send(
            &Message::new(Command::User)
                .with_param(user)
                .with_param("0")
                .with_param("*")
                .with_trailing(realname),
        )
        .await
    }

    /// Join a channel and install a handler for everything that happens in it.
    ///
    /// The handler runs on every message whose first parameter is `channel`
    /// (case-insensitive), including `PRIVMSG`, `NOTICE`, `JOIN`, `PART`, `MODE`
    /// and so on. It receives a structured [`ChatMessage`]: channel, sender,
    /// kind and text are typed fields, and `raw` keeps the original protocol
    /// message. Return a reply (easy via [`ChatMessage::reply`]) and the client
    /// sends it before [`Client::recv`] returns:
    ///
    /// ```no_run
    /// # async fn demo(client: &mut uu_irc::Client<tokio::net::TcpStream>) -> std::io::Result<()> {
    /// use uu_irc::ChatKind;
    ///
    /// client
    ///     .join("#uu", |chat| {
    ///         if chat.kind == ChatKind::Privmsg && chat.text() == Some("!ping") {
    ///             Some(chat.reply("pong"))
    ///         } else {
    ///             None
    ///         }
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Installing a handler for a channel that already has one replaces it.
    /// Handlers are not carried over by [`Client::split`].
    pub async fn join<H>(&mut self, channel: &str, handler: H) -> io::Result<()>
    where
        H: FnMut(&ChatMessage) -> Option<Message> + Send + 'static,
    {
        if self.channels.contains_key(&channel_key(channel)) {
            warn!(channel, "client: replacing the existing channel handler");
        }
        info!(channel, "client: joining channel");
        self.send(&Message::new(Command::Join).with_param(channel))
            .await?;
        self.channels.insert(
            channel_key(channel),
            Handler {
                callback: Box::new(handler),
            },
        );
        Ok(())
    }

    /// Leave a channel and drop its handler.
    pub async fn part(&mut self, channel: &str) -> io::Result<()> {
        info!(channel, "client: leaving channel");
        self.send(&Message::new(Command::Part).with_param(channel))
            .await?;
        if self.channels.remove(&channel_key(channel)).is_some() {
            debug!(channel, "client: removed the channel handler");
        }
        Ok(())
    }

    /// Run the handler registered for the message's channel, if any.
    fn dispatch(&mut self, msg: &Message) -> Option<Message> {
        let channel = msg.params.first()?;
        let key = channel_key(channel);
        if !self.channels.contains_key(&key) {
            return None;
        }
        let chat = ChatMessage::from_message(msg)?;
        let handler = self.channels.get_mut(&key)?;
        trace!(channel, "client: dispatching to the channel handler");
        let reply = handler.callback.as_mut()(&chat);
        if reply.is_some() {
            trace!(channel, "client: channel handler returned a reply");
        }
        reply
    }

    /// Drive the client until the server closes the connection.
    ///
    /// Answers `PING` automatically and dispatches channel handlers; `ERROR`
    /// and `Closed` end the loop. Malformed lines are skipped.
    pub async fn run(&mut self) -> io::Result<()> {
        info!("client: entering the event loop");
        loop {
            match self.recv().await? {
                Event::Message(msg) => {
                    if msg.command == Command::Ping {
                        let token = msg.trailing().unwrap_or_default().to_string();
                        trace!(token, "client: answering PING");
                        self.send(&Message::new(Command::Pong).with_param(token))
                            .await?;
                    } else if msg.command == Command::Error {
                        warn!(message = %Redacted(&msg), "client: server reported an error");
                        info!("client: event loop stopped on ERROR");
                        return Ok(());
                    }
                }
                Event::Invalid(_) => {}
                Event::Closed => {
                    info!("client: event loop stopped");
                    return Ok(());
                }
            }
        }
    }

    /// Send `PASS <password>`. Must be sent before `NICK`/`USER`.
    pub async fn pass(&mut self, password: &str) -> io::Result<()> {
        debug!("client: sending the server password (redacted)");
        self.send(&Message::new(Command::Pass).with_param(password))
            .await
    }

    /// Send `PASS`, then register with `NICK`/`USER`.
    pub async fn register_with_password(
        &mut self,
        nick: &str,
        user: &str,
        realname: &str,
        password: &str,
    ) -> io::Result<()> {
        info!(nick, "client: registering with a server password");
        self.pass(password).await?;
        self.register(nick, user, realname).await
    }

    /// Identify to NickServ: `PRIVMSG NickServ :IDENTIFY <password>`.
    pub async fn identify(&mut self, password: &str) -> io::Result<()> {
        self.identify_with("NickServ", password).await
    }

    /// Identify to an arbitrary services account.
    pub async fn identify_with(&mut self, account: &str, password: &str) -> io::Result<()> {
        info!(
            account,
            "client: identifying to services (password redacted)"
        );
        self.send(
            &Message::new(Command::Privmsg)
                .with_param(account)
                .with_trailing(format!("IDENTIFY {password}")),
        )
        .await
    }

    /// Register the current nickname with NickServ:
    /// `PRIVMSG NickServ :REGISTER <password> <email>`.
    ///
    /// Servers usually require the connection to be registered first, so call
    /// [`Client::wait_for_welcome`] after `NICK`/`USER` and before this.
    pub async fn nickserv_register(&mut self, password: &str, email: &str) -> io::Result<()> {
        self.nickserv_register_with("NickServ", password, email)
            .await
    }

    /// Register the current nickname with an arbitrary services account.
    pub async fn nickserv_register_with(
        &mut self,
        account: &str,
        password: &str,
        email: &str,
    ) -> io::Result<()> {
        info!(
            account,
            "client: registering the nickname with services (password redacted)"
        );
        self.send(
            &Message::new(Command::Privmsg)
                .with_param(account)
                .with_trailing(format!("REGISTER {password} {email}")),
        )
        .await
    }

    /// Wait for a numeric reply such as `001` (welcome) or `375` (MOTD start).
    ///
    /// `PING` is answered while waiting. Use [`Client::wait_for_welcome`] after
    /// `NICK`/`USER`: many servers reject `IDENTIFY`/`JOIN` with `451 You have
    /// not registered` until the welcome numeric has been sent.
    pub async fn wait_for_numeric(&mut self, code: u16) -> io::Result<Message> {
        let what = format!("numeric {code:03}");
        self.wait_for(|msg| msg.command.numeric() == Some(code), &what)
            .await
    }

    /// Wait for `001` (welcome), i.e. the end of registration.
    pub async fn wait_for_welcome(&mut self) -> io::Result<Message> {
        info!("client: waiting for the welcome numeric (001)");
        self.wait_for_numeric(1).await
    }

    /// Join a channel without a handler.
    ///
    /// ```
    /// # async fn demo(client: &mut uu_irc::Client<tokio::net::TcpStream>) -> std::io::Result<()> {
    /// client.join_only("#uu").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn join_only(&mut self, channel: &str) -> io::Result<()> {
        info!(channel, "client: joining channel without a handler");
        self.send(&Message::new(Command::Join).with_param(channel))
            .await
    }

    /// Authenticate with SASL PLAIN as part of registration.
    ///
    /// Performs the full handshake: `CAP LS 302`, `NICK`/`USER`, `CAP REQ
    /// :sasl`, `AUTHENTICATE PLAIN`, the base64 credentials, then `CAP END`
    /// after the server confirms (numeric `903`). Any `PING` received while
    /// waiting is answered. Errors from the server (numerics `902`/`904`–`907`)
    /// are returned as I/O errors, as is a timeout ([`SASL_TIMEOUT`]).
    pub async fn sasl_login(
        &mut self,
        nick: &str,
        user: &str,
        realname: &str,
        account: &str,
        password: &str,
    ) -> io::Result<()> {
        info!(nick, account, "client: starting SASL PLAIN login");
        // Start capability negotiation and registration.
        debug!("client: SASL step: CAP LS 302");
        self.send(
            &Message::new(Command::Cap)
                .with_param("LS")
                .with_param("302"),
        )
        .await?;
        self.register(nick, user, realname).await?;

        // Wait for the capability list.
        let caps = self
            .wait_for(|msg| is_cap_subcommand(msg, "LS"), "CAP LS")
            .await?;
        trace!(message = %Redacted(&caps), "client: SASL capability list received");

        // Upgrade to sasl only.
        debug!("client: SASL step: CAP REQ sasl");
        self.send(
            &Message::new(Command::Cap)
                .with_param("REQ")
                .with_param("sasl"),
        )
        .await?;
        let ack = self
            .wait_for(
                |msg| is_cap_subcommand(msg, "ACK") || is_cap_subcommand(msg, "NAK"),
                "CAP ACK/NAK",
            )
            .await?;
        if is_cap_subcommand(&ack, "NAK") {
            warn!("client: server refused the SASL capability");
            return Err(io::Error::other("server refused the sasl capability"));
        }
        debug!("client: SASL capability acknowledged");

        // Ask for the PLAIN mechanism.
        debug!("client: SASL step: AUTHENTICATE PLAIN");
        self.send(&Message::new(Command::Authenticate).with_param("PLAIN"))
            .await?;

        // Some servers invite the payload with `AUTHENTICATE +`, others accept
        // it immediately; either way, stop early on a failure numeric.
        let challenge = self
            .wait_for(
                |msg| msg.command == Command::Authenticate || is_sasl_result(msg),
                "AUTHENTICATE challenge",
            )
            .await?;
        if let Some(code) = challenge.command.numeric() {
            return sasl_result(code);
        }
        debug!("client: SASL challenge received, sending credentials");

        // authzid \0 authcid \0 password
        let mut plain = Vec::with_capacity(account.len() + password.len() + 2);
        plain.push(0);
        plain.extend_from_slice(account.as_bytes());
        plain.push(0);
        plain.extend_from_slice(password.as_bytes());
        self.send_authenticate_payload(&base64(&plain)).await?;

        // Wait for success (903; a preceding 900 is skipped by `is_sasl_result`).
        let result = self.wait_for(is_sasl_result, "SASL result").await?;
        let code = result.command.numeric().unwrap_or(0);
        sasl_result(code)?;
        info!(code, "client: SASL authentication successful");

        // Finish capability negotiation.
        debug!("client: SASL step: CAP END");
        self.send(&Message::new(Command::Cap).with_param("END"))
            .await
    }

    /// Split a base64 payload into `AUTHENTICATE` chunks of at most 400 bytes.
    async fn send_authenticate_payload(&mut self, payload: &str) -> io::Result<()> {
        trace!(len = payload.len(), "client: sending AUTHENTICATE payload");
        let mut rest = payload.as_bytes();
        while rest.len() > 400 {
            let (chunk, tail) = rest.split_at(400);
            let chunk = std::str::from_utf8(chunk).expect("base64 is ASCII");
            self.send(&Message::new(Command::Authenticate).with_param(chunk))
                .await?;
            rest = tail;
        }
        let last = std::str::from_utf8(rest).expect("base64 is ASCII");
        self.send(&Message::new(Command::Authenticate).with_param(last))
            .await?;
        // An exactly-full chunk must be followed by an empty one.
        if rest.len() == 400 {
            self.send(&Message::new(Command::Authenticate).with_param("+"))
                .await?;
        }
        Ok(())
    }

    /// Read messages, answering `PING`, until `predicate` matches.
    async fn wait_for<P>(&mut self, mut predicate: P, what: &str) -> io::Result<Message>
    where
        P: FnMut(&Message) -> bool,
    {
        trace!(what, "client: waiting for a specific server reply");
        loop {
            let event = tokio::time::timeout(SASL_TIMEOUT, self.recv())
                .await
                .map_err(|_| {
                    error!(what, timeout = ?SASL_TIMEOUT, "client: timed out waiting for the server");
                    io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for the server")
                })??;
            match event {
                Event::Message(msg) => {
                    if msg.command == Command::Ping {
                        let token = msg.trailing().unwrap_or_default().to_string();
                        trace!(token, "client: answering PING while waiting");
                        self.send(&Message::new(Command::Pong).with_param(token))
                            .await?;
                        continue;
                    }
                    if msg.command == Command::Error {
                        error!(message = %Redacted(&msg), "client: server error while waiting");
                        return Err(io::Error::other(msg.to_string()));
                    }
                    if predicate(&msg) {
                        trace!(what, "client: expected server reply received");
                        return Ok(msg);
                    }
                    trace!(command = %msg.command, what, "client: skipping unrelated reply");
                }
                Event::Invalid(_) => continue,
                Event::Closed => {
                    error!(what, "client: connection closed while waiting");
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed while waiting for the server",
                    ));
                }
            }
        }
    }

    /// Split into independent reader and writer halves.
    ///
    /// The two halves can live on separate tasks, so reading and writing happen
    /// fully concurrently.
    pub fn split(self) -> (ClientReader<T, C, F>, ClientWriter<T, C>)
    where
        C: Clone,
    {
        let (read, write) = tokio::io::split(self.reader.io);
        let reader = FrameReader {
            io: read,
            codec: self.reader.codec,
            framer: self.reader.framer,
            eof_seen: false,
        };
        let writer = FrameWriter::new(write, self.codec);
        (reader, writer)
    }

    /// The underlying transport.
    pub fn get_ref(&self) -> &T {
        &self.reader.io
    }
}

/// Connect to `target` with the default TCP connector.
pub async fn connect(target: &Target) -> io::Result<Client<tokio::net::TcpStream>> {
    debug!(%target, "client: connecting with TCP");
    let stream = TcpConnector.connect(target).await?;
    info!(%target, "client: connected");
    Ok(Client::new(stream))
}

/// Connect using a custom [`Connector`].
pub async fn connect_with<K>(connector: &K, target: &Target) -> Result<Client<K::Stream>, K::Error>
where
    K: Connector,
{
    debug!(%target, connector = std::any::type_name::<K>(), "client: connecting with a custom connector");
    let stream = connector.connect(target).await?;
    info!(%target, "client: connected");
    Ok(Client::new(stream))
}
