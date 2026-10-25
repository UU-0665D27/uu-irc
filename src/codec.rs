//! The [`Codec`] trait and the default IRC codec.
//!
//! A codec maps between protocol lines (bytes) and [`Message`] values. It is
//! symmetric: the same codec decodes what the server sends and encodes what we
//! send, so client- and server-side testing share one implementation.

use crate::error::ParseError;
use crate::framer::{Framer, LineFramer};
#[cfg(feature = "tracing")]
use crate::log::{debug, trace};
use crate::message::Message;

/// Converts between wire lines and [`Message`] values.
///
/// Implementations are cheap and cloneable so they can be shared with a reader
/// and a writer half after [`Client::split`](crate::Client::split).
pub trait Codec: Default + Clone + Send + Sync + 'static {
    /// Decode exactly one line (without terminator).
    fn decode(&self, line: &[u8]) -> Result<Message, ParseError>;

    /// Encode a message, appending the CRLF terminator.
    fn encode_into(&self, msg: &Message, out: &mut Vec<u8>);

    /// Encode a message into a fresh buffer.
    fn encode(&self, msg: &Message) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(msg, &mut out);
        out
    }

    /// Decode every complete line in a finite buffer.
    ///
    /// A trailing fragment without a terminator is decoded as well, which is the
    /// convenient behavior for tests and fuzzing.
    fn decode_all(&self, data: &[u8]) -> Vec<Result<Message, ParseError>> {
        decode_all_with::<Self, LineFramer>(self, data)
    }
}

/// The default IRC codec.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IrcCodec;

impl Codec for IrcCodec {
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    fn decode(&self, line: &[u8]) -> Result<Message, ParseError> {
        trace!(len = line.len(), "decoding line");
        let result = Message::parse(line);
        match &result {
            Ok(msg) => trace!(command = %msg.command, "decoded line"),
            Err(error) => debug!(%error, "failed to decode line"),
        }
        result
    }

    fn encode_into(&self, msg: &Message, out: &mut Vec<u8>) {
        #[cfg(feature = "tracing")]
        let start = out.len();
        out.extend_from_slice(&msg.to_bytes());
        trace!(
            command = %msg.command,
            len = out.len() - start,
            "encoded message"
        );
    }
}

/// Decode a whole buffer with an explicit framer.
pub fn decode_all_with<C, F>(codec: &C, data: &[u8]) -> Vec<Result<Message, ParseError>>
where
    C: Codec,
    F: Framer,
{
    let mut framer = F::new();
    framer.push(data);
    let mut out = Vec::new();
    while let Some(line) = framer.next_line() {
        out.push(codec.decode(&line));
    }
    if let Some(line) = framer.take_remaining() {
        out.push(codec.decode(&line));
    }
    trace!(
        bytes = data.len(),
        lines = out.len(),
        errors = out.iter().filter(|r| r.is_err()).count(),
        "decoded buffer"
    );
    out
}

/// Decode every line in a buffer with the default codec and framer.
///
/// This is the shared entry point used by tests and `cargo-fuzz`.
pub fn decode_all(data: &[u8]) -> Vec<Result<Message, ParseError>> {
    decode_all_with::<IrcCodec, LineFramer>(&IrcCodec, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Command;

    #[test]
    fn decodes_multiple_lines_including_partial_tail() {
        let data = b"PING :a\r\n:server 001 nick :hi\nPRIVMSG #c :no-newline";
        let msgs = decode_all(data);
        assert_eq!(msgs.len(), 3);
        assert!(msgs.iter().all(Result::is_ok));
        assert_eq!(msgs[2].as_ref().unwrap().params, ["#c", "no-newline"]);
    }

    #[test]
    fn encodes_with_crlf_and_round_trips() {
        let msg = Message::new(Command::Ping).with_param("token");
        let bytes = IrcCodec.encode(&msg);
        assert!(bytes.ends_with(b"\r\n"));
        assert_eq!(IrcCodec.decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn bad_lines_are_reported_not_panicked() {
        let results = decode_all(b"\r\n\r\nPING :x\r\n");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], Err(ParseError::Empty));
        assert_eq!(results[1], Err(ParseError::Empty));
        assert!(results[2].is_ok());
    }
}
