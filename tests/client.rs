#![cfg(feature = "net")]

//! End-to-end tests of the async client that never touch a real network.

use uu_irc::transport::MockStream;
use uu_irc::{
    ChatKind, ChatMessage, Client, Command, Event, FrameReader, IrcCodec, LineFramer, Message,
    memory_pair,
};

fn client_with_inbound(bytes: &[u8]) -> Client<MockStream> {
    let mut stream = MockStream::new();
    stream.push_inbound(bytes);
    stream.close_inbound();
    Client::new(stream)
}

#[tokio::test]
async fn recv_decodes_and_then_reports_close() {
    let mut client = client_with_inbound(b":srv 001 uu :hi\r\nPING :tok\r\n");

    assert_eq!(
        client.recv().await.unwrap(),
        Event::Message(Message::parse(b":srv 001 uu :hi").unwrap())
    );
    assert_eq!(
        client.recv().await.unwrap(),
        Event::Message(Message::new(Command::Ping).with_param("tok"))
    );
    assert_eq!(client.recv().await.unwrap(), Event::Closed);
}

#[tokio::test]
async fn invalid_lines_become_events_and_do_not_stop_the_client() {
    let mut client = client_with_inbound(b"\r\nPING :ok\r\n");

    assert!(matches!(client.recv().await.unwrap(), Event::Invalid(_)));
    assert_eq!(
        client.recv().await.unwrap(),
        Event::Message(Message::new(Command::Ping).with_param("ok"))
    );
}

#[tokio::test]
async fn feed_parses_without_any_io() {
    let mut client = Client::new(MockStream::new());
    // Complete line plus an incomplete (and invalid) one.
    let events = client.feed(b"NOTICE * :hello\r\n:");
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], Event::Message(_)));

    // The partial line is flushed on demand and turns out to be malformed.
    let tail = client.finish();
    assert_eq!(tail.len(), 1);
    assert!(matches!(tail[0], Event::Invalid(_)));
}

#[tokio::test]
async fn register_writes_nick_and_user() {
    let mut client = Client::new(MockStream::new());
    client.register("uu", "uu", "uu-irc").await.unwrap();

    let written = client.get_ref().written();
    // Trailing realname without spaces needs no ':' per the grammar.
    assert_eq!(written, b"NICK uu\r\nUSER uu 0 * uu-irc\r\n".as_slice());
}

#[tokio::test]
async fn send_raw_passes_bytes_through() {
    let mut client = Client::new(MockStream::new());
    client.send_raw(b"WEIRD garbage\x00\r\n").await.unwrap();
    assert_eq!(client.get_ref().written(), b"WEIRD garbage\x00\r\n");
}

#[tokio::test]
async fn split_halves_work_concurrently() {
    let (client_side, mut server_side) = memory_pair(1024);
    let client = Client::new(client_side);
    let (mut reader, mut writer) = client.split();

    // Writer half -> other end of the duplex.
    writer
        .send(&Message::new(Command::Ping).with_param("x"))
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::io::AsyncReadExt::read(&mut server_side, &mut buf)
        .await
        .unwrap();
    assert_eq!(&buf[..n], b"PING x\r\n");

    // Other end -> reader half.
    tokio::io::AsyncWriteExt::write_all(&mut server_side, b":srv PONG x\r\n")
        .await
        .unwrap();
    assert_eq!(
        reader.recv().await.unwrap(),
        Event::Message(Message::parse(b":srv PONG x").unwrap())
    );
}

#[tokio::test]
async fn custom_reader_framer_can_be_used_standalone() {
    let mut stream = MockStream::new();
    stream.push_inbound(b"PING :a\r\n");
    stream.close_inbound();

    let mut reader = FrameReader::new(stream, IrcCodec, LineFramer::with_limit(64));
    assert!(matches!(reader.recv().await.unwrap(), Event::Message(_)));
    assert_eq!(reader.recv().await.unwrap(), Event::Closed);
}

#[test]
fn chat_message_exposes_structured_fields() {
    let raw = Message::parse(b":alice!a@h PRIVMSG #UU :hello there").unwrap();
    let chat = ChatMessage::from_message(&raw).unwrap();
    assert_eq!(chat.channel, "#UU");
    assert_eq!(chat.sender(), Some("alice"));
    assert_eq!(chat.kind, ChatKind::Privmsg);
    assert_eq!(chat.text(), Some("hello there"));
    assert!(chat.is_privmsg());
    assert!(chat.is_from("ALICE"));
    assert_eq!(chat.raw, raw);
    assert_eq!(
        chat.reply("hi"),
        Message::new(Command::Privmsg)
            .with_param("#UU")
            .with_trailing("hi")
    );
    assert_eq!(
        chat.notice("hi"),
        Message::new(Command::Notice)
            .with_param("#UU")
            .with_trailing("hi")
    );

    let raw = Message::parse(b":bob!b@h JOIN #UU").unwrap();
    let join = ChatMessage::from_message(&raw).unwrap();
    assert_eq!(join.kind, ChatKind::Join);
    assert_eq!(join.sender(), Some("bob"));
    assert_eq!(join.text(), None);

    let raw = Message::parse(b":op!o@h KICK #UU bob :bye").unwrap();
    let kick = ChatMessage::from_message(&raw).unwrap();
    assert_eq!(kick.kind, ChatKind::Kick);
    assert_eq!(kick.text(), Some("bye"));
}

#[tokio::test]
async fn join_sends_join_and_runs_the_channel_handler() {
    let mut client = client_with_inbound(
        b":srv 001 uu :hi\r\n\
          :alice!a@h PRIVMSG #UU :!ping\r\n\
          :bob!b@h PRIVMSG #other :!ping\r\n",
    );

    client
        .join("#uu", |chat| {
            if chat.is_privmsg() && chat.text() == Some("!ping") {
                Some(chat.reply("pong"))
            } else {
                None
            }
        })
        .await
        .unwrap();

    // The JOIN itself is written immediately; no handler is involved.
    assert_eq!(client.get_ref().written(), b"JOIN #uu\r\n");

    // 001 has first param "uu", which is not a channel: no handler, no reply.
    assert!(matches!(client.recv().await.unwrap(), Event::Message(_)));
    assert_eq!(client.get_ref().written(), b"JOIN #uu\r\n");

    // A message for #UU reaches the #uu handler, which answers in-channel.
    // (The codec only adds the trailing ':' when the parameter needs it.)
    assert!(matches!(client.recv().await.unwrap(), Event::Message(_)));
    assert_eq!(
        client.get_ref().written(),
        b"JOIN #uu\r\nPRIVMSG #UU pong\r\n"
    );

    // A message for another channel is not dispatched.
    assert!(matches!(client.recv().await.unwrap(), Event::Message(_)));
    assert_eq!(
        client.get_ref().written(),
        b"JOIN #uu\r\nPRIVMSG #UU pong\r\n"
    );
}

#[tokio::test]
async fn part_sends_part_and_removes_the_handler() {
    let mut client = client_with_inbound(b":alice!a@h PRIVMSG #uu :hi\r\n");
    client
        .join("#uu", |chat| Some(chat.reply("still here")))
        .await
        .unwrap();
    client.part("#UU").await.unwrap();

    assert_eq!(
        client.get_ref().written(),
        b"JOIN #uu\r\nPART #UU\r\n".as_slice()
    );

    // The handler is gone, so the message produces no automatic reply.
    assert!(matches!(client.recv().await.unwrap(), Event::Message(_)));
    assert_eq!(
        client.get_ref().written(),
        b"JOIN #uu\r\nPART #UU\r\n".as_slice()
    );
}

#[tokio::test]
async fn pass_and_nickserv_identify_write_their_lines() {
    let mut client = Client::new(MockStream::new());
    client
        .register_with_password("uu", "uu", "uu-irc", "s3cret")
        .await
        .unwrap();
    client.identify("hunter2").await.unwrap();
    client
        .identify_with("Q@CServe.quakenet.org", "hunter3")
        .await
        .unwrap();

    assert_eq!(
        client.get_ref().written(),
        b"PASS s3cret\r\n\
          NICK uu\r\n\
          USER uu 0 * uu-irc\r\n\
          PRIVMSG NickServ :IDENTIFY hunter2\r\n\
          PRIVMSG Q@CServe.quakenet.org :IDENTIFY hunter3\r\n"
            .as_slice()
    );
}

#[tokio::test]
async fn nickserv_register_writes_the_register_command() {
    let mut client = Client::new(MockStream::new());
    client
        .nickserv_register("hunter2", "uu@example.org")
        .await
        .unwrap();
    client
        .nickserv_register_with("NickServ@services.example", "hunter3", "other@example.org")
        .await
        .unwrap();

    assert_eq!(
        client.get_ref().written(),
        b"PRIVMSG NickServ :REGISTER hunter2 uu@example.org\r\n\
          PRIVMSG NickServ@services.example :REGISTER hunter3 other@example.org\r\n"
            .as_slice()
    );
}

#[tokio::test]
async fn wait_for_welcome_answers_ping_and_skips_other_replies() {
    let mut client = client_with_inbound(
        b"PING :token\r\n\
          :srv 005 uu :are supported by this server\r\n\
          :srv 001 uu :Welcome\r\n\
          :NickServ!services@host NOTICE uu :You are now identified\r\n",
    );

    let welcome = client.wait_for_welcome().await.unwrap();
    assert_eq!(welcome.command, Command::Numeric(1));
    assert_eq!(client.get_ref().written(), b"PONG token\r\n");

    // The messages after 001 stay available to the normal event loop.
    assert!(matches!(client.recv().await.unwrap(), Event::Message(_)));
}

#[tokio::test]
async fn sasl_login_performs_the_plain_handshake() {
    let mut stream = MockStream::new();
    stream.push_inbound(
        b":srv CAP * LS :sasl multi-prefix\r\n\
          :srv CAP * ACK :sasl\r\n\
          AUTHENTICATE +\r\n\
          :srv 900 uu uu!uu@h uu :You are now logged in\r\n\
          :srv 903 uu :SASL authentication successful\r\n",
    );
    let mut client = Client::new(stream);

    client
        .sasl_login("uu", "uu", "uu-irc", "uu", "pw")
        .await
        .unwrap();

    assert_eq!(
        client.get_ref().written(),
        b"CAP LS 302\r\n\
          NICK uu\r\n\
          USER uu 0 * uu-irc\r\n\
          CAP REQ sasl\r\n\
          AUTHENTICATE PLAIN\r\n\
          AUTHENTICATE AHV1AHB3\r\n\
          CAP END\r\n"
            .as_slice()
    );
}

#[tokio::test]
async fn sasl_login_reports_refused_capability() {
    let mut stream = MockStream::new();
    stream.push_inbound(
        b":srv CAP * LS :multi-prefix\r\n\
          :srv CAP * NAK :sasl\r\n",
    );
    let mut client = Client::new(stream);

    let err = client
        .sasl_login("uu", "uu", "uu-irc", "uu", "pw")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("refused"));
}

#[tokio::test]
async fn sasl_login_reports_failed_authentication() {
    let mut stream = MockStream::new();
    stream.push_inbound(
        b":srv CAP * LS :sasl\r\n\
          :srv CAP * ACK :sasl\r\n\
          AUTHENTICATE +\r\n\
          :srv 904 uu :SASL authentication failed\r\n",
    );
    let mut client = Client::new(stream);

    let err = client
        .sasl_login("uu", "uu", "uu-irc", "uu", "wrong")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("failed"));
}
