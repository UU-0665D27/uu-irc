//! Error types for the IRC stack.
//!
//! The parsing layer is deliberately total: any byte slice produces either a
//! [`Message`](crate::Message) or a [`ParseError`], never a panic. That makes it
//! safe to feed arbitrary/fuzzed input into [`Message::parse`](crate::Message::parse).

use std::fmt;

/// A non-fatal decoding failure.
///
/// A conforming client keeps the connection alive after one of these: the line
/// is surfaced as [`Event::Invalid`](crate::Event::Invalid) and parsing resumes
/// on the next line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The line was empty (only a terminator, or nothing at all).
    Empty,
    /// A command could not be found (e.g. a bare `@tags` line or a lone prefix).
    MissingCommand,
    /// The command token contained characters that cannot form a command.
    InvalidCommand(String),
    /// The line exceeded [`MAX_LINE`](crate::message::MAX_LINE).
    TooLong { len: usize, max: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => f.write_str("empty message"),
            ParseError::MissingCommand => f.write_str("message has no command"),
            ParseError::InvalidCommand(c) => write!(f, "invalid command: {c:?}"),
            ParseError::TooLong { len, max } => {
                write!(f, "line too long: {len} bytes (max {max})")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// An error returned while turning a human address into a [`Target`](crate::Target).
#[cfg(feature = "net")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrError {
    /// The port was not a valid `u16`.
    InvalidPort(String),
    /// The host part was empty.
    MissingHost,
}

#[cfg(feature = "net")]
impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrError::InvalidPort(p) => write!(f, "invalid port: {p:?}"),
            AddrError::MissingHost => f.write_str("missing host"),
        }
    }
}

#[cfg(feature = "net")]
impl std::error::Error for AddrError {}
