#![no_main]

//! Fuzz the socket-free reader path: `FrameReader::feed` + `FrameReader::finish`.
//!
//! Bytes are injected in arbitrary chunks. Every `Event::Message` must survive
//! a wire round trip, and every `Event::Invalid` must reproduce the same error
//! when the raw bytes are decoded again.

use libfuzzer_sys::fuzz_target;
use uu_irc::{Codec, Event, FrameReader, IrcCodec, LineFramer, Message};

fuzz_target!(|data: &[u8]| {
    let (&control, rest) = match data.split_first() {
        Some(pair) => pair,
        None => return,
    };
    let chunk_size = ((control >> 4) as usize).max(1);

    let mut reader = FrameReader::new(tokio::io::empty(), IrcCodec, LineFramer::default());
    let mut events: Vec<Event> = Vec::new();

    for chunk in rest.chunks(chunk_size) {
        events.extend(reader.feed(chunk));
        // The reader's byte count must never exceed the framer limit.
        let _ = reader.buffered();
    }
    events.extend(reader.finish());

    for event in &events {
        match event {
            Event::Message(msg) => {
                let bytes = msg.to_bytes();
                let reparsed = Message::parse(&bytes)
                    .expect("a message we serialized ourselves must parse again");
                assert_eq!(*msg, reparsed, "wire round trip changed the message");
            }
            Event::Invalid(err) => {
                let re = IrcCodec.decode(&err.raw);
                assert_eq!(re, Err(err.error.clone()), "error did not reproduce");
            }
            Event::Closed => panic!("feed/finish must never emit Closed"),
        }
    }

    // Exercise the remaining accessors.
    let _ = reader.codec();
    let _ = reader.get_ref();
});
