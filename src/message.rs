//! The IRC message model: tags, prefix, command and parameters.
//!
//! The grammar follows RFC 1459/2812 plus the IRCv3 message-tags extension:
//!
//! ```text
//! [ '@' tags SP ] [ ':' prefix SP ] command [ SP params ] [ SP ':' trailing ] CR LF
//! ```
//!
//! [`Message::parse`] is total: it accepts any byte slice and never panics, which
//! is what makes the codec usable as a fuzzing entry point.

use std::fmt;
use std::fmt::Write as _;

use crate::error::ParseError;
#[cfg(feature = "tracing")]
use crate::log::{debug, trace};

/// Maximum accepted line length, including the trailing CRLF.
pub const MAX_LINE: usize = 8192;

/// IRCv3 message tags (`@key=value;key2`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tags {
    entries: Vec<(String, Option<String>)>,
}

impl Tags {
    /// An empty tag set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse the tag section (the part after `@`, before the first space).
    pub fn parse(s: &str) -> Self {
        let mut entries = Vec::new();
        for part in s.split(';') {
            if part.is_empty() {
                continue;
            }
            match part.split_once('=') {
                Some((k, v)) => entries.push((k.to_string(), Some(unescape(v)))),
                None => entries.push((part.to_string(), None)),
            }
        }
        Self { entries }
    }

    /// Look up a tag value. `None` means the key is absent, while
    /// `Some(None)` means the key is present without a value.
    pub fn get(&self, key: &str) -> Option<Option<&str>> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_deref())
    }

    /// Insert or replace a tag.
    pub fn set(&mut self, key: impl Into<String>, value: Option<impl Into<String>>) {
        let key = key.into();
        let value = value.map(Into::into);
        if let Some(entry) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = value;
        } else {
            self.entries.push((key, value));
        }
    }

    /// Number of tags.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no tags.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over `(key, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_deref()))
    }

    fn write_into(&self, out: &mut String) {
        for (i, (k, v)) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push(';');
            }
            out.push_str(k);
            if let Some(v) = v {
                out.push('=');
                out.push_str(&escape(v));
            }
        }
    }
}

fn escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            ';' => out.push_str("\\:"),
            ' ' => out.push_str("\\s"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

fn unescape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(':') => out.push(';'),
            Some('s') => out.push(' '),
            Some('\\') => out.push('\\'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            // Unknown escapes drop the backslash, per IRCv3.
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// The message source: either a server name or a `nick[!user][@host]` mask.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prefix {
    /// Server name or nickname.
    pub name: String,
    /// Username, when this is a user mask.
    pub user: Option<String>,
    /// Host, when this is a user mask.
    pub host: Option<String>,
}

impl Prefix {
    /// Parse the source part (the part after `:`, before the first space).
    pub fn parse(s: &str) -> Self {
        let (head, tail) = match s.split_once('!') {
            Some((name, rest)) => (name, Some(rest)),
            None => (s, None),
        };
        let (name, user, host) = match tail {
            // `nick!user[@host]`
            Some(rest) => match rest.split_once('@') {
                Some((user, host)) => (head, Some(user), Some(host)),
                None => (head, Some(rest), None),
            },
            // `nick` or `nick@host`
            None => match head.split_once('@') {
                Some((name, host)) => (name, None, Some(host)),
                None => (head, None, None),
            },
        };
        Self {
            name: name.to_string(),
            user: user.map(str::to_string),
            host: host.map(str::to_string),
        }
    }

    /// True when the source has no user/host part, i.e. it is a server name.
    pub fn is_server(&self) -> bool {
        self.user.is_none() && self.host.is_none()
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        if let Some(user) = &self.user {
            write!(f, "!{user}")?;
        }
        if let Some(host) = &self.host {
            write!(f, "@{host}")?;
        }
        Ok(())
    }
}

/// An IRC command.
///
/// Numeric replies (001–999) are kept as [`Command::Numeric`]; common named
/// commands get their own variant; anything else round-trips through
/// [`Command::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Pass,
    Nick,
    User,
    Oper,
    Mode,
    Service,
    Quit,
    Join,
    Part,
    Topic,
    Names,
    List,
    Invite,
    Kick,
    Motd,
    Version,
    Admin,
    Connect,
    Lusers,
    Time,
    Stats,
    Links,
    Trace,
    Help,
    Info,
    Privmsg,
    Notice,
    Tagmsg,
    Who,
    Whois,
    Whowas,
    Kill,
    Ping,
    Pong,
    Error,
    Away,
    Rehash,
    Restart,
    Summon,
    Users,
    Wallops,
    Userhost,
    Ison,
    Cap,
    Authenticate,
    Account,
    Batch,
    Chghost,
    Setname,
    Monitor,
    /// A three-digit numeric reply.
    Numeric(u16),
    /// Any command not covered above (kept verbatim, upper-cased on parse).
    Unknown(String),
}

impl Default for Command {
    fn default() -> Self {
        Command::Unknown(String::new())
    }
}

impl Command {
    /// Parse a command token.
    pub fn parse(s: &str) -> Self {
        if s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()) {
            return Command::Numeric(s.parse().unwrap_or(0));
        }
        match s.to_ascii_uppercase().as_str() {
            "PASS" => Command::Pass,
            "NICK" => Command::Nick,
            "USER" => Command::User,
            "OPER" => Command::Oper,
            "MODE" => Command::Mode,
            "SERVICE" => Command::Service,
            "QUIT" => Command::Quit,
            "JOIN" => Command::Join,
            "PART" => Command::Part,
            "TOPIC" => Command::Topic,
            "NAMES" => Command::Names,
            "LIST" => Command::List,
            "INVITE" => Command::Invite,
            "KICK" => Command::Kick,
            "MOTD" => Command::Motd,
            "VERSION" => Command::Version,
            "ADMIN" => Command::Admin,
            "CONNECT" => Command::Connect,
            "LUSERS" => Command::Lusers,
            "TIME" => Command::Time,
            "STATS" => Command::Stats,
            "LINKS" => Command::Links,
            "TRACE" => Command::Trace,
            "HELP" => Command::Help,
            "INFO" => Command::Info,
            "PRIVMSG" => Command::Privmsg,
            "NOTICE" => Command::Notice,
            "TAGMSG" => Command::Tagmsg,
            "WHO" => Command::Who,
            "WHOIS" => Command::Whois,
            "WHOWAS" => Command::Whowas,
            "KILL" => Command::Kill,
            "PING" => Command::Ping,
            "PONG" => Command::Pong,
            "ERROR" => Command::Error,
            "AWAY" => Command::Away,
            "REHASH" => Command::Rehash,
            "RESTART" => Command::Restart,
            "SUMMON" => Command::Summon,
            "USERS" => Command::Users,
            "WALLOPS" => Command::Wallops,
            "USERHOST" => Command::Userhost,
            "ISON" => Command::Ison,
            "CAP" => Command::Cap,
            "AUTHENTICATE" => Command::Authenticate,
            "ACCOUNT" => Command::Account,
            "BATCH" => Command::Batch,
            "CHGHOST" => Command::Chghost,
            "SETNAME" => Command::Setname,
            "MONITOR" => Command::Monitor,
            other => Command::Unknown(other.to_string()),
        }
    }

    /// The textual command name (upper-case). Numerics render as their name
    /// placeholder via [`Display`], use [`Command::numeric`] to get the code.
    pub fn as_str(&self) -> &str {
        match self {
            Command::Pass => "PASS",
            Command::Nick => "NICK",
            Command::User => "USER",
            Command::Oper => "OPER",
            Command::Mode => "MODE",
            Command::Service => "SERVICE",
            Command::Quit => "QUIT",
            Command::Join => "JOIN",
            Command::Part => "PART",
            Command::Topic => "TOPIC",
            Command::Names => "NAMES",
            Command::List => "LIST",
            Command::Invite => "INVITE",
            Command::Kick => "KICK",
            Command::Motd => "MOTD",
            Command::Version => "VERSION",
            Command::Admin => "ADMIN",
            Command::Connect => "CONNECT",
            Command::Lusers => "LUSERS",
            Command::Time => "TIME",
            Command::Stats => "STATS",
            Command::Links => "LINKS",
            Command::Trace => "TRACE",
            Command::Help => "HELP",
            Command::Info => "INFO",
            Command::Privmsg => "PRIVMSG",
            Command::Notice => "NOTICE",
            Command::Tagmsg => "TAGMSG",
            Command::Who => "WHO",
            Command::Whois => "WHOIS",
            Command::Whowas => "WHOWAS",
            Command::Kill => "KILL",
            Command::Ping => "PING",
            Command::Pong => "PONG",
            Command::Error => "ERROR",
            Command::Away => "AWAY",
            Command::Rehash => "REHASH",
            Command::Restart => "RESTART",
            Command::Summon => "SUMMON",
            Command::Users => "USERS",
            Command::Wallops => "WALLOPS",
            Command::Userhost => "USERHOST",
            Command::Ison => "ISON",
            Command::Cap => "CAP",
            Command::Authenticate => "AUTHENTICATE",
            Command::Account => "ACCOUNT",
            Command::Batch => "BATCH",
            Command::Chghost => "CHGHOST",
            Command::Setname => "SETNAME",
            Command::Monitor => "MONITOR",
            Command::Numeric(_) => "",
            Command::Unknown(s) => s.as_str(),
        }
    }

    /// The numeric code, if this is a numeric reply.
    pub fn numeric(&self) -> Option<u16> {
        match self {
            Command::Numeric(n) => Some(*n),
            _ => None,
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Numeric(n) => write!(f, "{n:03}"),
            other => f.write_str(other.as_str()),
        }
    }
}

/// A single parsed IRC message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    /// IRCv3 tags.
    pub tags: Tags,
    /// Optional source.
    pub prefix: Option<Prefix>,
    /// The command.
    pub command: Command,
    /// Parameters, in order. The trailing parameter (if any) is the last one.
    pub params: Vec<String>,
}

impl Message {
    /// Build a message from a command.
    pub fn new(command: Command) -> Self {
        Self {
            command,
            ..Self::default()
        }
    }

    /// Append a middle parameter (builder style).
    pub fn with_param(mut self, param: impl Into<String>) -> Self {
        self.params.push(param.into());
        self
    }

    /// Append a trailing parameter (builder style).
    pub fn with_trailing(self, trailing: impl Into<String>) -> Self {
        self.with_param(trailing)
    }

    /// Set the source (builder style).
    pub fn with_prefix(mut self, prefix: Prefix) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// Set the tags (builder style).
    pub fn with_tags(mut self, tags: Tags) -> Self {
        self.tags = tags;
        self
    }

    /// Parse a single line. Accepts arbitrary bytes and an optional trailing
    /// CR/LF; never panics.
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        trace!(len = bytes.len(), "parsing wire line");
        if bytes.len() > MAX_LINE {
            debug!(
                len = bytes.len(),
                max = MAX_LINE,
                "rejecting oversized line"
            );
            return Err(ParseError::TooLong {
                len: bytes.len(),
                max: MAX_LINE,
            });
        }
        // Lossy conversion: invalid UTF-8 must not turn into a hard failure when
        // fuzzing, it just gets replaced with U+FFFD.
        let raw = String::from_utf8_lossy(bytes);
        let mut line = raw.as_ref();
        if let Some(l) = line.strip_suffix('\n') {
            line = l;
        }
        if let Some(l) = line.strip_suffix('\r') {
            line = l;
        }
        let parsed = Self::parse_str(line);
        match &parsed {
            Ok(msg) => trace!(
                command = %msg.command,
                params = msg.params.len(),
                tags = msg.tags.len(),
                has_prefix = msg.prefix.is_some(),
                "line parsed"
            ),
            Err(error) => debug!(%error, "line rejected"),
        }
        parsed
    }

    /// Parse a line that is already `&str` and has no trailing terminator.
    pub fn parse_str(line: &str) -> Result<Self, ParseError> {
        if line.is_empty() {
            return Err(ParseError::Empty);
        }

        let mut rest = line;
        let mut msg = Message::default();

        if let Some(after) = rest.strip_prefix('@') {
            let (tags, rem) = after.split_once(' ').ok_or(ParseError::MissingCommand)?;
            msg.tags = Tags::parse(tags);
            rest = rem;
        }

        if let Some(after) = rest.strip_prefix(':') {
            let (prefix, rem) = after.split_once(' ').ok_or(ParseError::MissingCommand)?;
            msg.prefix = Some(Prefix::parse(prefix));
            rest = rem;
        }

        let (command, rem) = match rest.split_once(' ') {
            Some((c, r)) => (c, r),
            None => (rest, ""),
        };
        if command.is_empty() {
            return Err(ParseError::MissingCommand);
        }
        if !command.bytes().all(|b| b.is_ascii_alphanumeric()) {
            // Prevents a command token from masquerading as tags/prefix on the
            // way back out, which keeps encode/decode round trips faithful.
            return Err(ParseError::InvalidCommand(command.to_string()));
        }
        msg.command = Command::parse(command);
        trace!(command = %msg.command, "message command parsed");
        rest = rem;

        while !rest.is_empty() {
            if let Some(trailing) = rest.strip_prefix(':') {
                msg.params.push(trailing.to_string());
                break;
            }
            match rest.split_once(' ') {
                Some((p, r)) => {
                    msg.params.push(p.to_string());
                    rest = r;
                }
                None => {
                    msg.params.push(rest.to_string());
                    rest = "";
                }
            }
        }

        Ok(msg)
    }

    /// Serialize without the trailing CRLF.
    pub fn to_string_line(&self) -> String {
        trace!(
            command = %self.command,
            params = self.params.len(),
            tags = self.tags.len(),
            "serializing message"
        );
        let mut out = String::new();
        if !self.tags.is_empty() {
            out.push('@');
            self.tags.write_into(&mut out);
            out.push(' ');
        }
        if let Some(prefix) = &self.prefix {
            let _ = write!(out, ":{prefix} ");
        }
        let _ = write!(out, "{}", self.command);
        let last = self.params.len().saturating_sub(1);
        for (i, param) in self.params.iter().enumerate() {
            out.push(' ');
            let needs_colon =
                i == last && (param.is_empty() || param.contains(' ') || param.starts_with(':'));
            if needs_colon {
                out.push(':');
            }
            out.push_str(param);
        }
        out
    }

    /// Serialize a full protocol line, terminated with CRLF.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.to_string_line().into_bytes();
        out.extend_from_slice(b"\r\n");
        out
    }

    /// The trailing parameter, if the message has one that can contain spaces.
    pub fn trailing(&self) -> Option<&str> {
        self.params.last().map(String::as_str)
    }

    /// The command name as a string.
    pub fn command_str(&self) -> String {
        self.command.to_string()
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_line())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_command() {
        let m = Message::parse(b"PRIVMSG #chan :Hello, world!\r\n").unwrap();
        assert_eq!(m.command, Command::Privmsg);
        assert_eq!(m.params, ["#chan", "Hello, world!"]);
        assert!(m.prefix.is_none());
        assert!(m.tags.is_empty());
    }

    #[test]
    fn parses_prefix_and_tags() {
        let raw =
            b"@time=2020-01-01T00:00:00.000Z;account=bob :bob!bob@host PRIVMSG #chan :hi there\r\n";
        let m = Message::parse(raw).unwrap();
        assert_eq!(m.tags.get("account"), Some(Some("bob")));
        assert_eq!(m.tags.get("time"), Some(Some("2020-01-01T00:00:00.000Z")));
        assert_eq!(
            m.prefix,
            Some(Prefix {
                name: "bob".into(),
                user: Some("bob".into()),
                host: Some("host".into()),
            })
        );
        assert_eq!(m.command, Command::Privmsg);
        assert_eq!(m.params, ["#chan", "hi there"]);
    }

    #[test]
    fn parses_numeric_reply() {
        let m = Message::parse(b":server 001 nick :Welcome\r\n").unwrap();
        assert_eq!(m.command, Command::Numeric(1));
        assert_eq!(m.params, ["nick", "Welcome"]);
        assert_eq!(m.command_str(), "001");
        assert!(m.prefix.unwrap().is_server());
    }

    #[test]
    fn parses_ping_without_crlf() {
        let m = Message::parse(b"PING :token").unwrap();
        assert_eq!(m.command, Command::Ping);
        assert_eq!(m.params, ["token"]);
    }

    #[test]
    fn preserves_trailing_spaces() {
        let m = Message::parse(b"PRIVMSG #c :trailing  spaces \r\n").unwrap();
        assert_eq!(m.params[1], "trailing  spaces ");
    }

    #[test]
    fn empty_trailing_param() {
        let m = Message::parse(b"PRIVMSG #c :\r\n").unwrap();
        assert_eq!(m.params, ["#c", ""]);
    }

    #[test]
    fn tag_escaping_round_trips() {
        let mut tags = Tags::new();
        tags.set("k", Some("a b ;c\\d"));
        tags.set("flag", None::<String>);
        let m = Message::new(Command::Tagmsg)
            .with_param("#x")
            .with_tags(tags);
        let line = m.to_string_line();
        assert!(line.starts_with('@'));
        assert_eq!(Message::parse(line.as_bytes()).unwrap().tags, m.tags);
    }

    #[test]
    fn round_trips_through_wire() {
        let m = Message::parse(b":nick!u@h JOIN #chan\r\n").unwrap();
        let re = Message::parse(&m.to_bytes()).unwrap();
        assert_eq!(m, re);
    }

    #[test]
    fn rejects_empty_and_commandless() {
        assert_eq!(Message::parse(b"\r\n"), Err(ParseError::Empty));
        assert_eq!(Message::parse(b""), Err(ParseError::Empty));
        assert_eq!(
            Message::parse(b":only.prefix"),
            Err(ParseError::MissingCommand)
        );
        assert_eq!(Message::parse(b"@tag"), Err(ParseError::MissingCommand));
    }

    #[test]
    fn rejects_oversized_line() {
        let big = vec![b'a'; MAX_LINE + 1];
        assert!(matches!(
            Message::parse(&big),
            Err(ParseError::TooLong { .. })
        ));
    }

    #[test]
    fn rejects_invalid_command_token() {
        // The command token would be read back as tags, so it is rejected.
        assert_eq!(
            Message::parse(b"@ @weird CMD\r\n"),
            Err(ParseError::InvalidCommand("@weird".into()))
        );
        assert_eq!(
            Message::parse(b": ::colon\r\n"),
            Err(ParseError::InvalidCommand("::colon".into()))
        );
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        for len in 0..512usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let _ = Message::parse(&bytes);
        }
        // Includes invalid UTF-8.
        let _ = Message::parse(&[0xff, 0xfe, b' ', 0x00, b'P', b'I', b'N', b'G']);
    }
}
