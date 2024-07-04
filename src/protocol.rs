//! # ESP mDNS - Protocol
//! This module handles the construction, parsing, and validation of mDNS
//! packets, queries, and responses. It interacts with the network module to
//! receive raw data and convert it into meaningful mDNS packets and vice versa.

use alloc::{string::String, vec::Vec};

/// Describes the `OPCODE` field in [`MdnsFlags`].
/// 
/// This field indicates the kind of query contained within an [`MdnsPacket`].
/// Values are defined according to the DNS protocol specifications.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Opcode {
    /// Standard query (QUERY).
    /// 
    /// This is used to request information about a domain name, such as its IP
    /// address (A record), mail server (MX record), or other DNS records.
    Query,
    /// Inverse query (IQUERY).
    /// 
    /// This is historically used to map an IP address to a domain name, but it
    /// is now obsolete and rarely used in modern DNS operations. This
    /// functionality has largely been replaced by the PTR (Pointer) record in
    /// reverse DNS lookups.
    IQuery,
    /// Server status request (STATUS).
    /// 
    /// This type of query is used to request the status of a DNS server, asking
    /// the server to report its health, capabilities, and other status
    /// information. This opcode is used to diagnose server issues and ensure
    /// that the server is functioning correctly.
    Status,
    /// Unknown opcode.
    /// 
    /// Represents an unknown opcode. This variant is used to handle future
    /// extensions or unexpected values.
    /// 
    /// The enclosed `u8` value contains the raw 4-bit opcode number.
    Unknown(u8),
}

/// Describes the `RCODE` field in [`MdnsFlags`].
/// 
/// This indicates the result of a query.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Rcode {
    /// No error condition.
    NoError,
    /// Unable to interpret the query.
    FormatError,
    /// Unable to process the query due to a problem with the server.
    ServerFailure,
    /// The domain name referenced in the query does not exist (authoritative
    /// servers only).
    NameError,
    /// The name server does not support the requested kind of query.
    NotImplemented,
    /// The name server refuses to perform the specified operation for policy
    /// reasons.
    Refused,
    /// Unknown response code.
    /// 
    /// The enclosed `u8` value contains the raw 4-bit response code number.
    Unknown(u8),
}

/// Represents the flags in an [`MdnsHeader`].
/// 
/// This struct allows structured access to the individual bits and sub-fields
/// within the 16-bit flags field.
pub struct MdnsFlags(u16);

impl MdnsFlags {
    /// Bitmask for the Query/Response bit.
    /// 
    /// This bit indicates whether the message is a query (0) or a response (1).
    pub const QR_MASK: u16 = 0x8000;
    /// Bitmask for the Opcode field.
    /// 
    /// The Opcode field is 4 bits wide and indicates the kind of query in this
    /// message:
    /// - 0: Standard query (QUERY)
    /// - 1: Inverse query (IQUERY)
    /// - 2: Server status request (STATUS)
    pub const OPCODE_MASK: u16 = 0x7800;
    /// Bitmask for the Authoritative Answer bit.
    /// 
    /// This bit is valid in responses and specifies that the responding name
    /// server is an authority for the domain name in the question section.
    pub const AA_MASK: u16 = 0x0400;
    /// Bitmask for the TrunCaution bit.
    /// 
    /// This bit specifies that this message was truncated due to length greater
    /// than that permitted on the transmission channel.
    pub const TC_MASK: u16 = 0x0200;
    /// Bitmask for the Recursion Desired bit.
    /// 
    /// This bit may be set in a query and is copied into the response. If RD is
    /// set, it directs the name server to pursue the query recursively.
    pub const RD_MASK: u16 = 0x0100;
    /// Bitmask for the Recursion Available bit.
    /// 
    /// This bit is set or cleared in a response and denotes whether recursive
    /// query support is available in the name server.
    pub const RA_MASK: u16 = 0x0080;
    /// Bitmask for the Response Code field.
    /// 
    /// The Response Code field is 4 bits wide and indicates the result of the
    /// query.
    /// - 0: No error condition.
    /// - 1: Format error (unable to interpret the query).
    /// - 2: Server failure (unable to process the query due to a problem with
    ///   the server).
    /// - 3: Name error (the domain name referenced in the query does not exist,
    ///   authoritative servers only).
    /// - 4: Not implemented (the name server does not support the requested
    ///   kind of query).
    /// - 5: Refused (the name server refuses to perform the specified operation
    ///   for policy reasons).
    pub const RCODE_MASK: u16 = 0x000f;

    /// Creates an empty set of [`MdnsFlags`].
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self(0)
    }

    /// Gets the QR (Query/Response) bit.
    #[inline]
    #[must_use]
    pub fn qr(&self) -> bool {
        (self.0 & Self::QR_MASK) != 0
    }

    /// Sets the QR (Query/Response) bit.
    #[inline]
    pub fn set_qr(&mut self, value: bool) {
        if value {
            self.0 |= Self::QR_MASK;
        } else {
            self.0 &= !Self::QR_MASK;
        }
    }

    /// Gets the OPCODE field.
    #[inline]
    #[must_use]
    pub fn opcode(&self) -> Opcode {
        match (self.0 & Self::OPCODE_MASK) >> 11 {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            unknown => Opcode::Unknown(unknown as u8),
        }
    }

    /// Sets the OPCODE field.
    #[inline]
    pub fn set_opcode(&mut self, opcode: Opcode) {
        let opcode: u16 = match opcode {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            Opcode::Status => 2,
            Opcode::Unknown(other) => other as u16,
        };
        self.0 = (self.0 & !Self::OPCODE_MASK) | ((opcode & 0x0f) << 11);
    }

    /// Gets the AA (Authoritative Answer) bit.
    #[inline]
    #[must_use]
    pub fn aa(&self) -> bool {
        (self.0 & Self::AA_MASK) != 0
    }

    /// Sets the AA (Authoritative Answer) bit.
    #[inline]
    pub fn set_aa(&mut self, value: bool) {
        if value {
            self.0 |= Self::AA_MASK;
        } else {
            self.0 &= !Self::AA_MASK;
        }
    }

    /// Gets the TC (TrunCation) bit.
    #[inline]
    #[must_use]
    pub fn tc(&self) -> bool {
        (self.0 & Self::TC_MASK) != 0
    }

    /// Sets the TC (TrunCation) bit.
    #[inline]
    pub fn set_tc(&mut self, value: bool) {
        if value {
            self.0 |= Self::TC_MASK;
        } else {
            self.0 &= !Self::TC_MASK;
        }
    }

    /// Gets the RD (Recursion Desired) bit.
    #[inline]
    #[must_use]
    pub fn rd(&self) -> bool {
        (self.0 & Self::RD_MASK) != 0
    }

    /// Sets the RD (Recursion Desired) bit.
    #[inline]
    pub fn set_rd(&mut self, value: bool) {
        if value {
            self.0 |= Self::RD_MASK;
        } else {
            self.0 &= !Self::RD_MASK;
        }
    }

    /// Gets the RA (Recursion Available) bit.
    #[inline]
    #[must_use]
    pub fn ra(&self) -> bool {
        (self.0 & Self::RA_MASK) != 0
    }

    /// Sets the RA (Recursion Available) bit.
    #[inline]
    pub fn set_ra(&mut self, value: bool) {
        if value {
            self.0 |= Self::RA_MASK;
        } else {
            self.0 &= !Self::RA_MASK;
        }
    }

    /// Gets the RCODE (Response Code) field.
    #[inline]
    pub fn rcode(&self) -> Rcode {
        match self.0 & Self::RCODE_MASK {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            unknown => Rcode::Unknown(unknown as u8),
        }
    }

    /// Sets the RCODE (Response Code) field.
    pub fn set_rcode(&mut self, rcode: Rcode) {
        let rcode = match rcode {
            Rcode::NoError => 0,
            Rcode::FormatError => 1,
            Rcode::ServerFailure => 2,
            Rcode::NameError => 3,
            Rcode::NotImplemented => 4,
            Rcode::Refused => 5,
            Rcode::Unknown(value) => value,
        };
        self.0 = (self.0 & !Self::RCODE_MASK) | (rcode as u16);
    }
}

/// Represents the header of an [`MdnsPacket`].
/// 
/// The mDNS header contains important control information for mDNS packets,
/// including transaction IDs, flags, and counts for various sections of the
/// packet. This header is used in both queries and responses.
/// 
/// # Structure of the mDNS Header
/// The mDNS header is structured as follows:
/// 
/// | Field   | Size (bits) | Description                                            |
/// | ------- | ----------- | ------------------------------------------------------ |
/// | ID      | 16          | Transaction ID                                         |
/// | Flags   | 16          | Flags indicating query/response, operation codes, etc. |
/// | QDCOUNT | 16          | Number of entries in the question section.             |
/// | ANCOUNT | 16          | Number of entries in the answer section.               |
/// | NSCOUNT | 16          | Number of entries in the authority section.            |
/// | ARCOUNT | 16          | Number of entries in the additional records section.   |
/// 
/// # Fields
pub struct MdnsHeader {
    /// Transaction ID of the packet.
    /// 
    /// This identifier is assigned by the program that generates the query and
    /// is copied into the corresponding reply. It can be used by the requester
    /// to match up replies to outstanding queries.
    id: u16,
    /// Flags associated with the packet.
    /// 
    /// This 16-bit field contains various flags, including QR, Opcode, AA, TC,
    /// RD, RA, Z, and RCODE, which control the behaviour of the query/response
    /// and indicate various statuses.
    flags: MdnsFlags,
    /// Total questions contained within the packet.
    total_questions: u16,
    /// Total answers contained within the packet.
    total_answers: u16,
    /// Total authority records within the packet.
    total_authority_records: u16,
    /// Total additional records within the packet.
    total_additional_records: u16,
}

/// Represents the DNS types in mDNS.
/// 
/// This represents the type of record being queries or responded to. Each
/// variant corresponds to a specific type of DNS record.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DnsType {
    /// IPv4 record (A).
    /// 
    /// Requests or returns the IPv4 address associated with a domain name.
    A,
    /// IPv6 record (AAAA).
    /// 
    /// Requests or returns the IPv6 address associated with a domain name.
    AAAA,
    /// Canonical Name record (CNAME).
    /// 
    /// Requests or returns the canonical name for an alias.
    CNAME,
    /// Mail Exchange record (MX).
    /// 
    /// Requests or returns the mail server responsible for accepting messages
    /// on behalf of a domain.
    MX,
    /// Pointer record (PTR).
    /// 
    /// Requests or returns a pointer to another part of the DNS namespace,
    /// often used to reverse DNS lookups.
    PTR,
    /// Start of Authority record (SOA).
    /// 
    /// Requests or returns information about the authoritative DNS server for a
    /// domain.
    SOA,
    /// Text record (TXT).
    /// 
    /// Requests or returns text information associated with a domain name.
    TXT,
    /// Service locator record (SRV).
    /// 
    /// Requests or returns the location of services (like hosts and ports).
    SRV,
    /// Any type of record (ANY).
    /// 
    /// Requests or returns all records associated with a domain name.
    ANY,
    /// Unknown DNS type.
    /// 
    /// Represents an unknown DNS type. This variant is used to handle future
    /// extensions or unexpected values.
    /// 
    /// The enclosed `u16` value contains the raw DNS type number.
    Unknown(u16),
}

/// Represents the DNS classes in mDNS.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DnsClass {
    /// Internet (IN).
    /// 
    /// The standard Internet query class.
    IN,
    /// Chaos (CH).
    /// 
    /// Historically used for querying Chaosnet.
    CH,
    /// Hesiod (HS).
    /// 
    /// Used for querying the Hesiod name service.
    HS,
    /// Any class (ANY).
    /// 
    /// A wildcard query for any class.
    ANY,
    /// Unknown DNS class.
    /// 
    /// Represents an unknown DNS class. This variant is used to handle future
    /// extensions or unexpected values.
    /// 
    /// The enclosed `u16` value contains the raw DNS class number.
    Unknown(u16),
}

/// Represents an mDNS query.
#[derive(PartialEq, Debug)]
pub struct Query {
    /// The name being queried.
    name: String,
    /// The type of the query.
    query_type: DnsType,
    /// The class of the query, typically IN (Internet).
    query_class: DnsClass,
}

impl Query {
    /// Creates a new mDNS [`Query`].
    #[inline]
    #[must_use]
    pub fn new(
        name: String,
        query_type: DnsType,
        query_class: DnsClass
    ) -> Self {
        Self { name, query_type, query_class }
    }

    /// Returns an immutable reference to the name being queried.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &String {
        &self.name
    }

    /// Returns the query [`DnsType`].
    #[inline]
    #[must_use]
    pub fn query_type(&self) -> DnsType {
        self.query_type
    }

    /// Returns the query [`DnsClass`].
    #[inline]
    #[must_use]
    pub fn query_class(&self) -> DnsClass {
        self.query_class
    }
}

/// Represents an mDNS response.
#[derive(PartialEq, Debug)]
pub struct Response {
    /// The name associated with this response.
    name: String,
    /// The type of the response.
    response_type: DnsType,
    /// The class of the response, typically IN (Internet).
    response_class: DnsClass,
    /// The time to live for this response.
    ttl: u32,
    /// The data length of this response.
    data_length: u16,
    /// The actual data of the response.
    data: Vec<u8>,
}

impl Response {
    // TODO
}

/// Represents an mDNS packet.
pub struct MdnsPacket {
    header: MdnsHeader,
    /// The questions section of the [`MdnsPacket`].
    questions: Vec<Query>,
    /// The answers section of the [`MdnsPacket`].
    answers: Vec<Response>,
    /// The authorities section of the [`MdnsPacket`].
    authorities: Vec<Response>,
    /// The additional records section of the [`MdnsPacket`].
    additionals: Vec<Response>,
}

impl MdnsPacket {
    // TODO
}