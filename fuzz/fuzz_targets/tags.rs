#![no_main]

//! Fuzz IRCv3 tag parsing and escaping.
//!
//! `Tags::parse` must be total. For keys that survive `Tags::parse` unchanged
//! (no `;`, `=`, spaces, and non-empty), `set` → serialize → `parse` must
//! round-trip.

use libfuzzer_sys::fuzz_target;
use uu_irc::{Command, Message, Tags};

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

fuzz_target!(|data: &[u8]| {
    // 1. Arbitrary input to `Tags::parse` must not panic.
    let raw = String::from_utf8_lossy(data);
    let parsed = Tags::parse(&raw);
    let _ = parsed.len();
    let _ = parsed.is_empty();
    for (k, _) in parsed.iter() {
        let _ = parsed.get(k);
    }

    // 2. Round-trip built tags with well-formed keys.
    let mut tags = Tags::new();
    let mut it = split_chunks(data).into_iter();
    while let Some(k) = it.next() {
        let v = it.next();
        if k.is_empty() || k.contains([';', '=', ' ']) {
            continue; // `Tags::parse` would split or truncate this key
        }
        tags.set(k, v);
    }
    if tags.is_empty() {
        return;
    }

    let msg = Message::new(Command::Tagmsg).with_tags(tags.clone());
    let line = msg.to_string_line();

    // Extract the tag section (everything after `@`, before the first space).
    let section = line.strip_prefix('@').unwrap_or(&line);
    let section = section.split(' ').next().unwrap_or(section);

    let reparsed = Tags::parse(section);
    assert_eq!(tags, reparsed, "tags did not round-trip: {section:?}");
});
