//! Fulcrum Anvil — a declarative Debian/Ubuntu server-hardening CLI.
//!
//! The crate is organized around a small declarative engine (`engine`): modules
//! (`modules`) declare the files and commands they own, and the engine renders
//! the probe/apply bash and models results as typed values. Configuration
//! (`config`) is TOML; ordering safety lives in `order`; the SSH transport
//! shells out to the system `ssh` (`ssh`); the CLI is in `cli`.

pub mod cli;
pub mod config;
pub mod diff;
pub mod engine;
pub mod error;
pub mod escape;
pub mod local;
pub mod modules;
pub mod order;
pub mod plugin;
pub mod report;
pub mod ssh;

pub use error::{AnvilError, Result};
