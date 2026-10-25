//! Connect to an IRC server and print what it sends.
//!
//! ```text
//! IRC_SERVER='[::1]:6667' IRC_NICK=uu cargo run --example connect
//! ```
//!
//! Without `IRC_SERVER` it uses [`DEFAULT_TEST_SERVER`]. Registration is minimal
//! (nick + user); the loop answers `PING` and stops after a few events or when
//! the server closes the connection.

use std::env;

use uu_irc::{Command, DEFAULT_TEST_SERVER, Event, Message, Target};

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

    let target = Target::parse(&addr)?;
    println!("connecting to {target} as {nick} ...");
    let mut client = uu_irc::connect(&target).await?;
    client.register(&nick, &nick, "uu-irc").await?;

    for _ in 0..64 {
        match client.recv().await? {
            Event::Message(msg) => {
                println!("<- {msg}");
                match &msg.command {
                    Command::Ping => {
                        let token = msg.trailing().unwrap_or_default();
                        client
                            .send(&Message::new(Command::Pong).with_param(token))
                            .await?;
                        println!("-> PONG :{token}");
                    }
                    Command::Error => break,
                    _ => {}
                }
            }
            Event::Invalid(err) => {
                eprintln!(
                    "!! bad line {:?}: {}",
                    String::from_utf8_lossy(&err.raw),
                    err.error
                );
            }
            Event::Closed => {
                println!("connection closed");
                break;
            }
        }
    }

    Ok(())
}
