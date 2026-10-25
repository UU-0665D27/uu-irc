#![cfg(all(feature = "net", feature = "tracing"))]

//! Logging behavior: protocol detail is emitted at `trace`/`debug`, and
//! credentials never reach the log.

use std::io;
use std::sync::{Arc, Mutex};

use uu_irc::transport::MockStream;
use uu_irc::{Client, Command, Message};

/// A `MakeWriter` that appends every log line to an in-memory buffer.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn credentials_are_redacted_in_logs() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let mut client = Client::new(MockStream::new());
    client.pass("server-password").await.unwrap();
    client.identify("nickserv-password").await.unwrap();
    client
        .nickserv_register("register-password", "uu@example.org")
        .await
        .unwrap();
    client
        .send(
            &Message::new(Command::Authenticate)
                .with_param("PLAIN")
                .with_param("AHV1AHB3"),
        )
        .await
        .unwrap();
    client
        .send(
            &Message::new(Command::Privmsg)
                .with_param("#uu")
                .with_trailing("hello there"),
        )
        .await
        .unwrap();

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("sending message"),
        "missing send logs:\n{logs}"
    );
    assert!(!logs.contains("server-password"), "PASS leaked:\n{logs}");
    assert!(
        !logs.contains("nickserv-password"),
        "NickServ password leaked:\n{logs}"
    );
    assert!(
        !logs.contains("register-password"),
        "NickServ REGISTER password leaked:\n{logs}"
    );
    assert!(!logs.contains("AHV1AHB3"), "SASL payload leaked:\n{logs}");
    assert!(logs.contains("***"), "secrets were not masked:\n{logs}");
    assert!(
        logs.contains("REGISTER ***"),
        "REGISTER should keep the command visible:\n{logs}"
    );
    assert!(
        logs.contains("hello there"),
        "non-secret payload should be logged:\n{logs}"
    );
}
