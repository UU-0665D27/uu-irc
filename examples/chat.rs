//! Connect, optionally authenticate, join a channel and answer in it.
//!
//! ```text
//! IRC_SERVER='[::1]:6667' IRC_NICK=uu IRC_CHANNEL='#uu' cargo run --example chat
//! IRC_SERVER=irc.example.org IRC_PASSWORD=example_secret_server \
//!     IRC_NICKSERV_PASSWORD=example_secret_nick cargo run --example chat
//! ```
//!
//! `IRC_PASSWORD` is sent as `PASS` before registration; `IRC_NICKSERV_PASSWORD`
//! identifies to NickServ after registration. Set `IRC_NICKSERV_REGISTER_EMAIL`
//! instead of identifying when the nickname is new: the example then sends
//! `NickServ REGISTER <password> <email>`.

use std::env;

use uu_irc::{ChatKind, DEFAULT_TEST_SERVER, Target};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `RUST_LOG=trace` for wire-level detail; `info` is the default.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr = env::var("IRC_SERVER").unwrap_or_else(|_| DEFAULT_TEST_SERVER.to_string());
    let nick = env::var("IRC_NICK").unwrap_or_else(|_| "uu".into());
    let channel = env::var("IRC_CHANNEL").unwrap_or_else(|_| "#uu".into());
    let server_password = env::var("IRC_PASSWORD").ok();
    let nickserv_password = env::var("IRC_NICKSERV_PASSWORD").ok();
    let nickserv_email = env::var("IRC_NICKSERV_REGISTER_EMAIL").ok();

    let target = Target::parse(&addr)?;
    println!("connecting to {target} as {nick} ...");
    let mut client = uu_irc::connect(&target).await?;

    // Authorization: server password (PASS) first, then NICK/USER.
    match server_password.as_deref() {
        Some(password) => {
            client
                .register_with_password(&nick, &nick, "uu-irc", password)
                .await?
        }
        None => client.register(&nick, &nick, "uu-irc").await?,
    }

    // Wait for 001 before talking to services or joining: some servers answer
    // early commands with `451 You have not registered`.
    client.wait_for_welcome().await?;

    // Services authorization: register a new nickname or identify.
    match (nickserv_password.as_deref(), nickserv_email.as_deref()) {
        (Some(password), Some(email)) => client.nickserv_register(password, email).await?,
        (Some(password), None) => client.identify(password).await?,
        (None, _) => {}
    }

    // Join the channel and install a handler. It receives a structured
    // `ChatMessage` (channel, sender, kind, text); returning a message makes the
    // client send it automatically.
    client
        .join(&channel, |chat| {
            println!(
                "[{}] {}: {}",
                chat.channel,
                chat.sender().unwrap_or("server"),
                chat.text().unwrap_or("")
            );
            if chat.kind == ChatKind::Privmsg && chat.text() == Some("!hello") {
                Some(chat.reply("hello from uu-irc!"))
            } else {
                None
            }
        })
        .await?;

    // `run` answers PING, dispatches channel handlers and stops when the server
    // closes the connection. Use `recv` instead if you need to inspect every
    // event yourself.
    client.run().await?;
    println!("connection closed");

    Ok(())
}
