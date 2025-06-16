//! # Error
//! This module contains all the potential error types that can come from
//! the `conntrack` library.

use std::fmt::Debug;

/// Error consolidates and propagates all underlying error types.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("netlink error: {0}")]
    Netlink(#[from] neli::err::SocketError),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Deserialization(#[from] neli::err::DeError),

    #[error(transparent)]
    Serialization(#[from] neli::err::SerError),
}
