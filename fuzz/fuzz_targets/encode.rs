#![no_main]

//! Fuzz the builder API and the encode path.
//!
//! Arbitrary bytes are split into length-prefixed UTF-8-lossy chunks and
//! assembled into a `Message` via `Message::new` / `with_param` /
//! `with_trailing` / `with_prefix` / `with_tags`. The message is encoded with
//! `IrcCodec`, decoded, and re-encoded.
//!
//! The builder deliberately does not validate parameters or tag keys, so a
//! built message may not round-trip *exactly*. What must always hold is that
//! encoding is idempotent after one round trip: `parse(encode(m))` and
//! `parse(encode(parse(encode(m))))` are the same value.

use libfuzzer_sys::fuzz_target;
use uu_irc::{Codec, Command, IrcCodec, Message, Prefix, Tags};

fn split_chunks(mut data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while let Some((&n, rest)) = data.split_first() {
        let n = (n as usize).min(rest.len());
        let (chunk, tail) = rest.split_at(n);
        out.push(String::from_utf8_lossy(chunk).into_owned());
        data = tail;
    }
    out
}

fn exercise_accessors(msg: &Message) {
    let _ = msg.trailing();
    let _ = msg.command_str();
    let _ = msg.command.numeric();
    let _ = msg.command.as_str();
    let _ = msg.tags.is_empty();
    let _ = msg.tags.len();
    for (k, _) in msg.tags.iter() {
        let _ = msg.tags.get(k);
    }
    if let Some(p) = &msg.prefix {
        let _ = p.is_server();
        let _ = p.to_string();
    }
    let _ = msg.to_string();
    let _ = format!("{}", msg.command);
}

fuzz_target!(|data: &[u8]| {
    let parts = split_chunks(data);
    let mut it = parts.into_iter();

    // `Command::parse` always normalises (upper-cases, maps numerics), so the
    // command itself is stable across re-parsing.
    let command = Command::parse(&it.next().unwrap_or_default());
    let mut msg = Message::new(command);

    let n_params = (data.first().copied().unwrap_or(0) as usize) % 8;
    for _ in 0..n_params {
        if let Some(p) = it.next() {
            msg = msg.with_param(p);
        }
    }
    if let Some(t) = it.next() {
        msg = msg.with_trailing(t);
    }
    if let Some(p) = it.next() {
        msg = msg.with_prefix(Prefix::parse(&p));
    }

    let mut tags = Tags::new();
    while let Some(k) = it.next() {
        let v = it.next();
        tags.set(k, v);
    }
    if !tags.is_empty() {
        msg = msg.with_tags(tags);
    }

    exercise_accessors(&msg);

    let codec = IrcCodec;

    // First round trip. The builder permits inputs that produce syntactically
    // invalid lines (tag keys with spaces, commands with punctuation, ...);
    // skip those rather than flag the builder here.
    let wire1 = codec.encode(&msg);
    let parsed1 = match codec.decode(&wire1) {
        Ok(m) => m,
        Err(_) => return,
    };
    exercise_accessors(&parsed1);

    // Wire form must be stable after re-parsing.
    let wire2 = codec.encode(&parsed1);
    let parsed2 = match codec.decode(&wire2) {
        Ok(m) => m,
        Err(e) => panic!("re-encoded message failed to decode: {e:?}"),
    };
    assert_eq!(
        parsed1, parsed2,
        "re-encoding is not idempotent after one round trip"
    );

    // Exercise the `decode_all` default entry point too.
    let _ = codec.decode_all(&wire2);
});
