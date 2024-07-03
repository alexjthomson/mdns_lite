//! # ESP - mDNS
//! This library provides an implementation of Multicast DNS (mDNS) for ESP32
//! microcontrollers.
//! 
//! mDNS allows devices on a local network to discover each other without the
//! need for a central DNS server.
//! 
//! ## Features
//! - Query for services and hostnames on the local network.
//! - Respond to mDNS queries with service information.
//! - Support for adding TXT records with service metadata.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

pub mod service;
// TODO: Create something that consumes MdnsService and broadcasts it