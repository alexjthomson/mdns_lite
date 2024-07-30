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

pub use class::MdnsClass;
pub use flags::MdnsFlags;
pub use header::MdnsHeader;
pub use name::{
    MdnsName,
    MdnsNameError,
};
pub use opcode::MdnsOpcode;
pub use packet::MdnsPacket;
pub use query::MdnsQuery;
pub use rcode::MdnsRcode;
pub use response::MdnsResponse;
pub use r#type::MdnsType;

/// Describes various errors that could happen while parsing an mDNS packet.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum MdnsParseError {
    // TODO: Document each of the errors, why they occur, etc.
    HeaderTooSmall,
    MalformedQuery,
    MalformedResponse,
    NameError(MdnsNameError),
}

impl core::fmt::Display for MdnsParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HeaderTooSmall => write!(f, "The mDNS header is too small. mDNS headers are exactly 12 bytes."),
            Self::MalformedQuery => write!(f, "There are not enough bytes to contain the query type and query class."),
            Self::MalformedResponse => write!(f, "There are not enough bytes to contain the remainder of the response after the name."),
            Self::NameError(error) => write!(f, "Failed to parse mDNS name: {error}"),
        }
    }
}