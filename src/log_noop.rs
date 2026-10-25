//! No-op logging macros used when the `tracing` feature is disabled.
//!
//! Declared with `#[macro_use]` in `lib.rs`, so every module can call
//! `trace!`/`debug!`/`info!`/`warn!`/`error!` and the arguments vanish at
//! compile time. Keeping them out of a `use` statement avoids the built-in
//! `warn` attribute name clash.

// `info!`/`error!` are only used by the `net` feature, which may be off.
#![allow(unused_macros)]

macro_rules! trace {
    ($($arg:tt)*) => {
        ()
    };
}

macro_rules! debug {
    ($($arg:tt)*) => {
        ()
    };
}

macro_rules! info {
    ($($arg:tt)*) => {
        ()
    };
}

macro_rules! warn {
    ($($arg:tt)*) => {
        ()
    };
}

macro_rules! error {
    ($($arg:tt)*) => {
        ()
    };
}
