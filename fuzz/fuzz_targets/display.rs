#![no_main]

//! Fuzz the `Display` impls and error formatting.
//!
//! Every `Display` / `Debug` impl must be total and must not panic on values
//! built from arbitrary input.

use libfuzzer_sys::fuzz_target;
use uu_irc::{Command, Message, ParseError, Prefix};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    // `ParseError::Display`
    let errors = [
        ParseError::Empty,
        ParseError::MissingCommand,
        ParseError::InvalidCommand(s.clone().into_owned()),
        ParseError::TooLong {
            len: data.len(),
            max: usize::MAX / 2,
        },
    ];
    for e in &errors {
        let _ = e.to_string();
        let _ = format!("{e}");
        let _ = format!("{e:?}");
        let _ = std::error::Error::source(e);
    }

    // `Prefix::Display` + `is_server`
    let prefix = Prefix::parse(&s);
    let _ = format!("{prefix}");
    let _ = prefix.is_server();

    // `Command::Display` / `as_str` / `numeric`
    let command = Command::parse(&s);
    let _ = format!("{command}");
    let _ = command.as_str();
    let _ = command.numeric();

    // `Message::Display` + accessors
    if let Ok(msg) = Message::parse(data) {
        let _ = format!("{msg}");
        let _ = msg.to_string();
        let _ = msg.command_str();
        let _ = msg.trailing();
    }
});
