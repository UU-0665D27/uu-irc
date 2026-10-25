# uu-irc

A small, trait-based IRC stack for Rust: message model, framing, codec, and an
async client — each layer behind a trait so it can be swapped, tested, and
fuzzed independently.

## Layout

| Layer | Trait | Default impl | What it does |
|-------|-------|--------------|--------------|
| Model | — | `Message`, `Command`, `Prefix`, `Tags` | parse/serialize one IRC line |
| Framing | `Framer` | `LineFramer` | bytes → lines (CRLF/LF), length-bounded |
| Codec | `Codec` | `IrcCodec` | lines ↔ `Message` |
| Transport | `Transport` | `TcpStream`, `MockStream` | full-duplex bytes |
| Connector | `Connector` | `TcpConnector` | dial a `Target` |
| Client | — | `Client` | socket + framing + codec |

The model, framer and codec have **no dependencies** and are always available.
The async transport and client live behind the default `net` feature (tokio).
Structured logging comes from the default `tracing` feature; disable it (or use
`--no-default-features`) to keep even the full build dependency-free apart from
tokio.

```
cargo build --no-default-features                    # core only, zero deps
cargo build --no-default-features --features tracing # core + logging
cargo build                                          # full stack + logging
```

## Quick start

```rust
use uu_irc::{Command, Event, Message, Target};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse("irc.example.org:6667")?;
    let mut client = uu_irc::connect(&target).await?;
    client.register("uu", "uu", "uu-irc").await?;

    while let Event::Message(msg) = client.recv().await? {
        println!("<- {msg}");
        if msg.command == Command::Ping {
            client
                .send(&Message::new(Command::Pong).with_param(msg.trailing().unwrap_or("")))
                .await?;
        }
    }
    Ok(())
}
```

A runnable version is in `examples/connect.rs`:

```sh
IRC_SERVER='[::1]:6667' IRC_NICK=uu cargo run --example connect
```

## Authorization and channels

```rust
// PASS before NICK/USER (server password), then NICK/USER.
client.register_with_password("uu", "uu", "uu-irc", "server-pass").await?;
// Wait for 001 before services/join: early commands can get
// "451 You have not registered".
client.wait_for_welcome().await?;

// NickServ: PRIVMSG NickServ :IDENTIFY <password>
client.identify("services-pass").await?;
// ...or register a new nickname (NickServ REGISTER <password> <email>).
// client.nickserv_register("services-pass", "uu@example.org").await?;

// Join and install a handler. It receives a structured `ChatMessage`
// (channel, sender, kind, text); returning a message sends it automatically.
client
    .join("#uu", |chat| {
        if chat.is_privmsg() && chat.text() == Some("!ping") {
            Some(chat.reply("pong"))
        } else {
            None
        }
    })
    .await?;

// Answer PING, dispatch handlers, stop on close/ERROR.
client.run().await?;
```

`Client::part("#uu")` leaves the channel and drops its handler, `join_only`
joins without one, `wait_for_numeric(code)` waits for any numeric reply (for
example `005` or `375`), and `sasl_login` performs the full SASL PLAIN handshake
(`CAP LS 302` → `CAP REQ :sasl` → `AUTHENTICATE PLAIN` → `CAP END`) with a
30-second timeout and no extra dependencies.

Channel handlers receive a structured `ChatMessage` instead of raw text indices:
`channel`, `sender`, `kind` (`ChatKind`), `text`, and `raw` (the original
protocol `Message`). Helpers such as `reply`, `notice`, `is_privmsg`, `text()`
and `is_from(nick)` keep callbacks readable.

See `examples/chat.rs`:

```sh
IRC_SERVER=irc.example.org IRC_NICK=uu IRC_PASSWORD=serverpass \
    IRC_NICKSERV_PASSWORD=example_secret_nick IRC_CHANNEL='#uu' cargo run --example chat
# register a new nickname instead of identifying:
IRC_SERVER=irc.example.org IRC_NICK=uu IRC_NICKSERV_PASSWORD=example_secret_nick \
    IRC_NICKSERV_REGISTER_EMAIL=uu@example.org cargo run --example chat
```

### About the test server

The default test server is the Yggdrasil interface address
`[228:39cf:5792:fbd1:d5c7:a750:7ab9:4389]:6667`, hard-coded as
`DEFAULT_TEST_SERVER` in `src/lib.rs`. Override it with `IRC_SERVER`.

## Bidirectional reading

Reading is deliberately split from writing so both can run concurrently, and so
the reader can be driven without a socket:

- `Client::split()` returns independent `ClientReader` / `ClientWriter` halves
  (backed by `tokio::io::split`) that can live on separate tasks.
- `FrameReader::feed(&[u8])` injects arbitrary bytes as if they came off the
  socket and returns every complete `Event` — no I/O. `FrameReader::finish()`
  flushes a trailing partial line.
- `FrameWriter::send_raw(&[u8])` sends arbitrary bytes verbatim.
- `MockStream` is an in-memory transport: `push_inbound` to control what arrives,
  `take_written` to inspect what the client sent.

Malformed input never panics and never kills the connection: a bad line becomes
`Event::Invalid { raw, error }` and parsing continues.

## Fuzzing

The pure decode path is the fuzzing entry point:

```rust
for result in uu_irc::decode_all(bytes) { /* Result<Message, ParseError> */ }
```

Invariants checked by `tests/fuzz_decode.rs` (a fast, seedless corpus pass) and
by the `cargo-fuzz` target in `fuzz/fuzz_targets/decode.rs`:

1. decoding any byte string never panics;
2. every message that decodes survives a serialize → parse round trip unchanged.

```sh
cargo fuzz run decode      # requires `cargo install cargo-fuzz`
cargo test                 # includes the corpus pass + round-trip checks
```

`MockStream` makes it easy to fuzz the *protocol* too, not just the parser: feed
adversarial server output and assert on what the client writes back.

## Logging

The default `tracing` feature instruments every layer:

| Level | What is emitted |
|-------|-----------------|
| `error!` | socket read/write failures, SASL failures, timeouts |
| `warn!` | malformed lines, framer cap reached, handler replacement, SASL refusal |
| `info!` | connect/register/join/identify lifecycle, connection closed |
| `debug!` | every protocol message sent/received (`\*` redacted credentials), SASL steps |
| `trace!` | raw byte counts, framing, parse/encode detail, channel dispatch |

Credentials (`PASS`, SASL `AUTHENTICATE` payloads and `NickServ IDENTIFY`
passwords) are masked as `***` before logging. Wire the subscriber yourself, or
use the examples:

```sh
RUST_LOG=trace cargo run --example connect
RUST_LOG=uu_irc=debug cargo run --example chat
```

## Testing

```sh
cargo test --all-features
cargo clippy --all-targets --all-features
```

Integration tests in `tests/client.rs` drive the full client over `MockStream`
and an in-memory duplex pair; no network access is required.
