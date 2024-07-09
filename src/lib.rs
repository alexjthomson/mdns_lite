//! # mDNS Lite
//! This library provides a lightweight implementation of Multicast DNS (mDNS).
//! 
//! mDNS allows devices on a local network to discover each other without the
//! need for a central DNS server.

pub mod network;
pub mod protocol;
pub mod service;

pub use network::*;
pub use protocol::*;
pub use service::*;