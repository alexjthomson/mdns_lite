//! # mDNS Lite
//! This library provides a lightweight implementation of Multicast DNS (mDNS).
//! 
//! mDNS allows devices on a local network to discover each other without the
//! need for a central DNS server.

#![no_std]

extern crate alloc;

pub mod network;
pub mod protocol;
pub mod service;

#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::{
        network::MdnsBroadcaster,
        protocol::{
            MdnsClass,
            MdnsName,
            MdnsNameError,
            MdnsType,
            MdnsFlags,
            MdnsHeader,
            MdnsPacket,
            MdnsOpcode,
            MdnsQuery,
            MdnsRcode,
            MdnsResponse,
        },
        service::{
            MdnsService,
            MdnsServiceError,
            TxtRecords,
        },
    };
}                           

pub use network::*;
pub use protocol::*;
pub use service::*;