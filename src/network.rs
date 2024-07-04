//! # ESP mDNS - Network
//! This module manages the underlying network operations, such as socket
//! management and network interface configuration. It provides the raw data to
//! the protocol module for processing and sends out the processed mDNS packets.
// TODO: Correct the documentation above

use alloc::vec::Vec;

use crate::MdnsService;

// TODO:
// This struct should register services. These services are then broadcast. The
// broadcaster will also respond to queries about the service.
pub struct MdnsBroadcaster {
    services: Vec<MdnsService>,
    // TODO: Continue here
}