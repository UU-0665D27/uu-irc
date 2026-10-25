//! Corpus-driven robustness test.
//!
//! This is the same logic the `cargo-fuzz` target runs, so a failure here is a
//! failure there and vice versa. It needs no network and no tokio.

use uu_irc::{Message, decode_all};

/// Deterministic xorshift so failures are reproducible without a seed file.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// The core invariant: decoding never panics, and every decoded message
/// survives a serialize → parse round trip unchanged.
fn check(bytes: &[u8]) {
    for msg in decode_all(bytes).into_iter().flatten() {
        let reencoded = msg.to_bytes();
        let reparsed = match Message::parse(&reencoded) {
            Ok(m) => m,
            Err(e) => {
                panic!("reparse failed ({e:?}): input={bytes:?} msg={msg:?} encoded={reencoded:?}")
            }
        };
        assert_eq!(msg, reparsed, "round trip changed the message");
    }
}

#[test]
fn handles_a_broad_corpus_without_panicking() {
    let seeds: &[&[u8]] = &[
        b"",
        b"\r\n",
        b"\n",
        b"PING",
        b"PING :",
        b":",
        b": ",
        b"@",
        b"@ ",
        b"@a=b;c;d=e :nick!u@h PRIVMSG #c :hi\r\n",
        b"@a=\\:\\s\\\\\\r\\n KICK #c b :reason\r\n",
        b":srv 001 n :welcome\r\nQUIT :bye\r\nPING :x",
        b"NICK",
        b"NICK ",
        b"NICK  ",
        b" NICK x",
        b"PRIVMSG #c ::starts-with-colon\r\n",
        b"PRIVMSG #c :\r\n",
        b"CAP * LS :multi-prefix sasl\r\n",
        "\u{1F600} ⚡".as_bytes(),
        &[0xff, 0xfe, 0xfd, b'\r', b'\n'],
        &[0x00, 0x01, 0x02, b' ', b'A'],
    ];

    for seed in seeds {
        check(seed);
    }

    // Pseudo-random fuzz pass.
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let alphabet: &[u8] = b"@:;!   \r\nPRIVMSG#abc-=0123\xff";
    for _ in 0..20_000 {
        let len = (rng.next() % 64) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            let idx = (rng.next() as usize) % alphabet.len();
            buf.push(alphabet[idx]);
        }
        check(&buf);
    }
}

#[test]
fn unterminated_input_is_still_decoded() {
    let results = decode_all(b"NICK uu");
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok());
}
