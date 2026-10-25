//! Logging facade for the `tracing` feature.
//!
//! `tracing` is optional so the core layers stay dependency-free for
//! `--no-default-features` builds and `cargo-fuzz`. With the feature enabled,
//! each module imports these macros; without it, [`crate::log_noop`] provides
//! no-op macros with the same names.

#[cfg(feature = "tracing")]
#[allow(unused_imports)] // `info!`/`error!` are only used by the `net` feature.
pub(crate) use tracing::{debug, error, info, trace, warn};
