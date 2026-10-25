#![no_main]

//! Fuzz the pure decode path: arbitrary bytes in, no panics out.
//!
//! `cargo fuzz run decode` (from the repository root via `cargo fuzz`, which
//! drives the crate in `fuzz/`).

use libfuzzer_sys::fuzz_target;
use uu_irc::{Message, decode_all};

fuzz_target!(|data: &[u8]| {
    for result in decode_all(data) {
        if let Ok(msg) = result {
            // Anything we manage to parse must survive a wire round trip.
            let bytes = msg.to_bytes();
            let reparsed = Message::parse(&bytes)
                .expect("a message we serialized ourselves must parse again");
            assert_eq!(msg, reparsed, "round trip changed the message");
        }
    }
});
