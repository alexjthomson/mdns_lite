//! # mDNS Lite - Protocol
//! This module handles the construction, parsing, and validation of mDNS
//! packets, queries, and responses. It interacts with the network module to
//! receive raw data and convert it into meaningful mDNS packets and vice versa.

pub mod class;
pub mod flags;
pub mod header;
pub mod name;
pub mod opcode;
pub mod packet;
pub mod query;
pub mod rcode;
pub mod response;
pub mod r#type;

pub use class::DnsClass;
pub use flags::MdnsFlags;
pub use header::MdnsHeader;
pub use name::DnsName;
pub use opcode::Opcode;
pub use packet::MdnsPacket;
pub use query::Query;
pub use rcode::Rcode;
pub use response::Response;
pub use r#type::DnsType;

use thiserror::Error;

/// Describes various errors that could happen while parsing an mDNS packet.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Error, Debug)]
pub enum ParseMdnsError {
    #[error("The mDNS header is too small.
    mDNS headers are exactly 12 bytes.")]
    HeaderTooSmall,
    #[error("An mDNS query is malformed.
    There are not enough bytes to contain the query type and query class.")]
    MalformedQuery,
    #[error("An mDNS response is malformed.
    There are not enough bytes to contain the remainder of the response after the name.")]
    MalformedResponse,
    #[error("Label length exceeds data length `{length}` (maximum_length: `{max_length}`).")]
    InvalidLabelLength {
        length: usize,
        max_length: usize,
    },
    #[error("Label is not valid UTF-8.")]
    InvalidUtf8Label,
    #[error("Labels do not end with a zero byte.")]
    InvalidEndOfLabels,
}

/// Error type for [`DnsName`].
#[derive(PartialEq, Eq, Debug, Error)]
pub enum DnsNameError {
    #[error("DNS name must end with a `.`.")]
    MustEndWithDot,
    #[error("Each label must be 63 characters or less.")]
    LabelTooLong,
}