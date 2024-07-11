# mDNS Lite - Notes
This document contains implementation notes. For context, I have no idea how
mDNS actually works, I'm reverse engineering it to create this library rather
than reading boring documentation.

## Home Assistant
Home assistant often does not acknowledge or react to any packets sent by this
library. The packets are not malformed, they just don't appear to be what home
assistant is looking for.

### Response #1
Home assistant has responded to packets with questions when no authoritative
nameserver responses are included with the packets. Home assistant responded to
the packets with two questions:
1. An A record question, asking what IPv4 address the service has.
2. An AAAA record question, asking what IPv6 address the service has.

Currently, the library does not know how to respond to questions. This should be
worked on as the next priority.