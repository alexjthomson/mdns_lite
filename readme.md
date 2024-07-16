# mDNS Lite
This library provides a lightweight implementation of Multicast DNS (mDNS).

mDNS allows devices on a local network to discover each other without the need
for a central DNS server.

## Features
- Query for services and hostnames on the local network.
- Respond to mDNS queries with service information.
- Support for adding TXT records with service metadata.

## Todo
- [ ] Create unit tests for `MdnsPacket::from_bytes`.