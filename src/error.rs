//! Typed library errors (R99). The CLI boundary wraps these in `anyhow`.

use thiserror::Error;

/// All failure modes the library can surface. Every variant carries an
/// actionable, human-readable message.
#[derive(Debug, Error)]
pub enum AnvilError {
    #[error("could not read config file {path}: {source}")]
    ConfigRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("could not parse config: {0}")]
    ConfigParse(String),

    #[error("invalid config: {0}")]
    Validation(String),

    #[error("invalid usage: {0}")]
    Usage(String),

    #[error("include cycle detected: {0}")]
    IncludeCycle(String),

    #[error("unknown profile {name:?}; built-in profiles are: {available}")]
    UnknownProfile { name: String, available: String },

    #[error("execution order is empty; nothing to do")]
    EmptyOrder,

    #[error("ordering cycle detected: {0}")]
    OrderingCycle(String),

    #[error("safety violation: {0}")]
    Safety(String),

    #[error("ssh transport failed: {0}")]
    Ssh(String),
}

/// Convenience alias for library results.
pub type Result<T> = std::result::Result<T, AnvilError>;
