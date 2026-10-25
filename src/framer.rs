//! Incremental line framing.
//!
//! Sockets deliver arbitrary byte chunks; a [`Framer`] turns that byte soup into
//! complete protocol lines. Framing is direction-agnostic: the same framer is
//! used for bytes read *from* the server and (in tests/fuzzing) for bytes we
//! feed by hand, which is what makes the stack easy to drive without a socket.

use std::collections::VecDeque;

#[cfg(feature = "tracing")]
use crate::log::{debug, trace, warn};
use crate::message::MAX_LINE;

/// Split a byte stream into CRLF/LF terminated lines.
///
/// Implementations must be memory-safe against adversarial input: an incomplete
/// line is bounded by the configured limit instead of growing without bound.
pub trait Framer: Default + Clone + Send + 'static {
    /// Create a framer with the default limit.
    fn new() -> Self {
        Self::default()
    }

    /// Create a framer that forces a line break after `max` bytes.
    fn with_limit(max: usize) -> Self
    where
        Self: Sized;

    /// Feed freshly read bytes.
    fn push(&mut self, data: &[u8]);

    /// Pop the next complete line (terminator stripped), if any.
    fn next_line(&mut self) -> Option<Vec<u8>>;

    /// Pop a trailing partial line. Used when the peer closes or when decoding a
    /// finite buffer that may lack a final newline.
    fn take_remaining(&mut self) -> Option<Vec<u8>> {
        let mut line = self.peek_partial()?;
        self.clear_partial();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        trace!(len = line.len(), "flushing trailing partial line");
        Some(line)
    }

    /// Number of bytes buffered in the current partial line.
    fn buffered(&self) -> usize;

    /// Bytes of the current partial line.
    fn peek_partial(&self) -> Option<Vec<u8>>;

    /// Drop the current partial line.
    fn clear_partial(&mut self);
}

/// The default framer: splits on `\n`, tolerates a preceding `\r`, and caps the
/// length of a single line at [`MAX_LINE`].
#[derive(Debug, Clone)]
pub struct LineFramer {
    lines: VecDeque<Vec<u8>>,
    partial: Vec<u8>,
    max: usize,
}

impl Default for LineFramer {
    fn default() -> Self {
        Self {
            lines: VecDeque::new(),
            partial: Vec::new(),
            max: MAX_LINE,
        }
    }
}

impl LineFramer {
    /// A framer with the default limit ([`MAX_LINE`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// A framer that forces a line break after `max` bytes.
    pub fn with_limit(max: usize) -> Self {
        let max = max.max(1);
        debug!(max, "creating line framer with custom limit");
        Self {
            max,
            ..Self::default()
        }
    }
}

impl Framer for LineFramer {
    fn with_limit(max: usize) -> Self {
        LineFramer::with_limit(max)
    }

    fn push(&mut self, data: &[u8]) {
        trace!(
            len = data.len(),
            buffered = self.partial.len(),
            queued = self.lines.len(),
            "framing incoming bytes"
        );
        for &byte in data {
            if byte == b'\n' {
                let mut line = std::mem::take(&mut self.partial);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                trace!(len = line.len(), "complete line framed");
                self.lines.push_back(line);
            } else if self.partial.len() < self.max {
                self.partial.push(byte);
            } else {
                // Hard cap reached: emit what we have and start a new line.
                warn!(
                    max = self.max,
                    "line exceeded the framer limit; forcing a split"
                );
                let line = std::mem::take(&mut self.partial);
                self.lines.push_back(line);
                self.partial.push(byte);
            }
        }
    }

    fn next_line(&mut self) -> Option<Vec<u8>> {
        self.lines.pop_front()
    }

    fn buffered(&self) -> usize {
        self.partial.len()
    }

    fn peek_partial(&self) -> Option<Vec<u8>> {
        if self.partial.is_empty() {
            None
        } else {
            Some(self.partial.clone())
        }
    }

    fn clear_partial(&mut self) {
        self.partial.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_lf_and_crlf() {
        let mut f = LineFramer::new();
        f.push(b"a\r\nb\nc");
        assert_eq!(f.next_line().as_deref(), Some(b"a".as_slice()));
        assert_eq!(f.next_line().as_deref(), Some(b"b".as_slice()));
        assert_eq!(f.next_line(), None);
        assert_eq!(f.take_remaining().as_deref(), Some(b"c".as_slice()));
    }

    #[test]
    fn handles_split_across_chunks() {
        let mut f = LineFramer::new();
        f.push(b"PING :to");
        assert_eq!(f.next_line(), None);
        f.push(b"ken\r\n");
        assert_eq!(f.next_line().as_deref(), Some(b"PING :token".as_slice()));
    }

    #[test]
    fn caps_line_length() {
        let mut f = LineFramer::with_limit(8);
        f.push(b"0123456789ABCDEF");
        // The cap forces the first 8 bytes out; the rest stays buffered.
        assert_eq!(f.next_line().as_deref(), Some(b"01234567".as_slice()));
        assert_eq!(f.next_line(), None);
        assert!(f.buffered() <= 8);
        assert_eq!(f.take_remaining().as_deref(), Some(b"89ABCDEF".as_slice()));
        assert_eq!(f.buffered(), 0);
    }

    #[test]
    fn empty_line_yields_empty_vec() {
        let mut f = LineFramer::new();
        f.push(b"\r\n");
        assert_eq!(f.next_line(), Some(Vec::new()));
    }
}
