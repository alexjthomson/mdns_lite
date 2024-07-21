# mDNS Lite
This library provides a lightweight implementation of Multicast DNS (mDNS).

mDNS allows devices on a local network to discover each other without the need
for a central DNS server.

## Features
- Query for services and hostnames on the local network.
- Respond to mDNS queries with service information.
- Support for adding TXT records with service metadata.

## Todo
- [ ] Add additional unit tests to `protocol.rs` to validate that errors are
  returned when they are expected to.
- [ ] Update the rust-docs with links so where in the mDNS specification various
  constants and definitions are defined.
- [x] Fix unit tests in `protocol.rs` not passing.
- [x] Create unit tests for `MdnsPacket::from_bytes`.