//! # ESP mDNS - Protocol
//! This module handles the construction, parsing, and validation of mDNS
//! packets, queries, and responses. It interacts with the network module to
//! receive raw data and convert it into meaningful mDNS packets and vice versa.

use thiserror::Error;

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
#[derive(Clone, Copy, PartialEq, Default, Debug)]
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

    /// Converts raw `bytes` into [`MdnsFlags`].
    #[inline]
    #[must_use]
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }

    /// Gets the QR (Query/Response) bit.
    #[inline]
    #[must_use]
    pub fn qr(&self) -> bool {
        (self.0 & Self::QR_MASK) != 0
    }

    /// Sets the QR (Query/Response) bit.
    /// 
    /// - If this is set to `true`, it indicates that the [`MdnsPacket`] is a
    ///   response.
    /// - If this is set to `false`, it indicates that the [`MdnsPacket`] is a
    ///   query.
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
    /// 
    /// - If this is set to `true`, it indicates that the responding name server
    ///   is an authority for the domain name in the question section.
    /// - If this is set to `false`, it indicates that the responding name
    ///   server isn't an authority for the domain name in the question section.
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

impl From<u16> for MdnsFlags {
    #[inline]
    #[must_use]
    fn from(flags: u16) -> Self {
        Self(flags)
    }
}

impl From<MdnsFlags> for u16 {
    #[inline]
    #[must_use]
    fn from(flags: MdnsFlags) -> Self {
        flags.0
    }
}

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
/// The total size of an mDNS header is 
#[derive(Clone, Copy, PartialEq, Debug)]
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
    total_question_records: u16,
    /// Total answers contained within the packet.
    total_answer_records: u16,
    /// Total authority records within the packet.
    total_authority_records: u16,
    /// Total additional records within the packet.
    total_additional_records: u16,
}

impl MdnsHeader {
    /// Defines the exact size of an mDNS header in bytes.
    pub const MDNS_HEADER_SIZE: usize = 12;

    /// Converts the [`MdnsHeader`] into raw bytes that can form the start of an
    /// mDNS packet.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::MDNS_HEADER_SIZE] {
        let flags = self.flags.0;
        [
            (self.id >> 8) as u8,
            (self.id & 0xff) as u8,
            (flags >> 8) as u8,
            (flags & 0xff) as u8,
            (self.total_question_records >> 8) as u8,
            (self.total_question_records & 0xff) as u8,
            (self.total_answer_records >> 8) as u8,
            (self.total_answer_records & 0xff) as u8,
            (self.total_authority_records >> 8) as u8,
            (self.total_authority_records & 0xff) as u8,
            (self.total_additional_records >> 8) as u8,
            (self.total_additional_records & 0xff) as u8,
        ]
    }

    /// Parses an mDNS header from bytes to an [`MdnsHeader`] instance.
    pub fn from_bytes(bytes: &[u8], offset: &mut usize) -> Result<Self, ParseMdnsError> {
        // Get the mDNS header bytes from the `bytes` slice passed into the
        // function:
        if bytes.len() - *offset < Self::MDNS_HEADER_SIZE {
            return Err(ParseMdnsError::HeaderTooSmall);
        }
        let header: &[u8; Self::MDNS_HEADER_SIZE] = &bytes[*offset..(*offset + Self::MDNS_HEADER_SIZE)]
            .try_into()
            .unwrap();

        // Apply the offset and return the header:
        *offset += Self::MDNS_HEADER_SIZE;
        Ok(Self {
            id: u16::from_be_bytes([header[0], header[1]]),
            flags: MdnsFlags::from_bytes([header[2], header[3]]),
            total_question_records: u16::from_be_bytes([header[4], header[5]]),
            total_answer_records: u16::from_be_bytes([header[6], header[7]]),
            total_authority_records: u16::from_be_bytes([header[8], header[9]]),
            total_additional_records: u16::from_be_bytes([header[10], header[11]]),
        })
    }
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

impl From<u16> for DnsType {
    #[must_use]
    fn from(id: u16) -> Self {
        match id {
            0x0001 => Self::A,
            0x001c => Self::AAAA,
            0x0005 => Self::CNAME,
            0x000f => Self::MX,
            0x000c => Self::PTR,
            0x0006 => Self::SOA,
            0x0010 => Self::TXT,
            0x0021 => Self::SRV,
            0x00ff => Self::ANY,
            _ => Self::Unknown(id),
        }
    }
}

impl From<DnsType> for u16 {
    #[must_use]
    fn from(dns_type: DnsType) -> Self {
        match dns_type {
            DnsType::A     => 0x0001,
            DnsType::AAAA  => 0x001c,
            DnsType::CNAME => 0x0005,
            DnsType::MX    => 0x000f,
            DnsType::PTR   => 0x000c,
            DnsType::SOA   => 0x0006,
            DnsType::TXT   => 0x0010,
            DnsType::SRV   => 0x0021,
            DnsType::ANY   => 0x00ff,
            DnsType::Unknown(value) => value,
        }
    }
}

impl From<DnsType> for [u8; 2] {
    #[must_use]
    fn from(dns_class: DnsType) -> Self {
        match dns_class {
            DnsType::A     => [0x00, 0x01],
            DnsType::AAAA  => [0x00, 0x1c],
            DnsType::CNAME => [0x00, 0x05],
            DnsType::MX    => [0x00, 0x0f],
            DnsType::PTR   => [0x00, 0x0c],
            DnsType::SOA   => [0x00, 0x06],
            DnsType::TXT   => [0x00, 0x10],
            DnsType::SRV   => [0x00, 0x21],
            DnsType::ANY   => [0x00, 0xff],
            DnsType::Unknown(value) => [(value >> 8) as u8, (value & 0xff) as u8],
        }
    }
}

impl From<[u8; 2]> for DnsType {
    #[must_use]
    fn from(slice: [u8; 2]) -> Self {
        match slice {
            [0x00, 0x01] => Self::A,
            [0x00, 0x1c] => Self::AAAA,
            [0x00, 0x05] => Self::CNAME,
            [0x00, 0x0f] => Self::MX,
            [0x00, 0x0c] => Self::PTR,
            [0x00, 0x06] => Self::SOA,
            [0x00, 0x10] => Self::TXT,
            [0x00, 0x21] => Self::SRV,
            [0x00, 0xff] => Self::ANY,
            _ => Self::Unknown(u16::from_be_bytes(slice)),
        }
    }
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

impl From<u16> for DnsClass {
    #[must_use]
    fn from(id: u16) -> Self {
        match id {
            0x0001 => Self::IN,
            0x0003 => Self::CH,
            0x0004 => Self::HS,
            0x00ff => Self::ANY,
            _ => Self::Unknown(id),
        }
    }
}

impl From<DnsClass> for u16 {
    #[must_use]
    fn from(dns_class: DnsClass) -> Self {
        match dns_class {
            DnsClass::IN  => 0x0001,
            DnsClass::CH  => 0x0003,
            DnsClass::HS  => 0x0004,
            DnsClass::ANY => 0x00ff,
            DnsClass::Unknown(id) => id,
        }
    }
}

impl From<DnsClass> for [u8; 2] {
    #[must_use]
    fn from(dns_class: DnsClass) -> Self {
        match dns_class {
            DnsClass::IN  => [0x00, 0x01],
            DnsClass::CH  => [0x00, 0x03],
            DnsClass::HS  => [0x00, 0x04],
            DnsClass::ANY => [0x00, 0xff],
            DnsClass::Unknown(id) => [(id >> 8) as u8, (id & 0xff) as u8],
        }
    }
}

impl From<[u8; 2]> for DnsClass {
    #[must_use]
    fn from(slice: [u8; 2]) -> Self {
        match slice {
            [0x00, 0x01] => Self::IN,
            [0x00, 0x03] => Self::CH,
            [0x00, 0x04] => Self::HS,
            [0x00, 0xff] => Self::ANY,
            _ => Self::Unknown(u16::from_be_bytes(slice)),
        }
    }
}

/// Error type for [`DnsName`].
#[derive(PartialEq, Eq, Debug, Error)]
pub enum DnsNameError {
    #[error("DNS name must end with a `.`.")]
    MustEndWithDot,
    #[error("Each label must be 63 characters or less.")]
    LabelTooLong,
}

/// Represents a DNS name with its labels.
#[derive(Clone, PartialEq, Debug)]
pub struct DnsName {
    /// Labels that make up the [`DnsName`].
    labels: Vec<String>,
}

impl DnsName {
    /// Creates a new [`DnsName`].
    /// 
    /// ## Note
    /// Prefer using [`DnsName::from_name`] since this function does not
    /// validate the `labels` provided to it.
    #[inline]
    #[must_use]
    pub fn new(labels: Vec<String>) -> Self {
        Self { labels }
    }

    /// Creates a new [`DnsName`] from a string representation of the name.
    /// 
    /// The string representation should be formatted as follows:
    /// `instance_name._service_type_name._service_type_protocol.service_domain.`,
    /// and may contain any number of labels. The string must end with a dot and
    /// only contain alphanumeric characters, hyphens, and underscores.
    pub fn from_name(name: &str) -> Result<Self, DnsNameError> {
        if name.is_empty() || !name.ends_with('.') {
            return Err(DnsNameError::MustEndWithDot);
        }
        let labels: Vec<String> = name
            .trim_end_matches('.')
            .split('.')
            .map(|s| s.to_string())
            .collect();

        for label in &labels {
            if label.len() > 63 {
                return Err(DnsNameError::LabelTooLong);
            }
        }
        Ok(DnsName::new(labels))
    }

    /// Convert the [`DnsName`] to its wire format
    #[must_use]
    pub fn to_wire_format(&self) -> Vec<u8> {
        let mut wire_format = Vec::new();
        for label in &self.labels {
            debug_assert!(label.is_ascii());
            wire_format.push(label.len() as u8);
            wire_format.extend_from_slice(label.as_bytes());
        }
        wire_format.push(0); // End of name
        wire_format
    }

    /// Create a [`DnsName`] from wire format
    pub fn from_wire_format(data: &[u8], offset: &mut usize) -> Result<Self, ParseMdnsError> {
        let mut labels = Vec::new();
        let mut i: usize = *offset;
        while i < data.len() {
            // Get the length of the next label:
            let len: usize = data[i] as usize;

            // Check for a null byte, this indicates that this is the end of the
            // wire format labels. We should therefore stop here:
            if len == 0 {
                break;
            }

            // We should iterate the offset by `1` since we just read the label
            // length byte and it was not a null byte:
            i += 1;

            // We need to perform a range check to ensure that the `data` buffer
            // has enough space to contain the label:
            if i + len > data.len() {
                return Err(ParseMdnsError::InvalidLabelLength {
                    length: len,
                    max_length: data.len() - i,
                });
            }

            // Read the label from the `data` buffer:
            let label = match std::str::from_utf8(&data[i..(i + len)]) {
                Ok(label) => label.to_string(),
                Err(_) => return Err(ParseMdnsError::InvalidUtf8Label),
            };

            // We can now push the constructed label to the `labels` vector:
            labels.push(label);

            // We also need to move the offset to the start of the next label:
            i += len;
        }
        if i == data.len() || data[i] != 0 {
            return Err(ParseMdnsError::InvalidEndOfLabels);
        }
        *offset = i + 1;
        Ok(DnsName { labels })
    }
}

impl std::fmt::Display for DnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.", self.labels.join("."))
    }
}

impl From<Vec<String>> for DnsName {
    fn from(labels: Vec<String>) -> Self {
        DnsName::new(labels)
    }
}

impl From<DnsName> for Vec<String> {
    fn from(dns_name: DnsName) -> Self {
        dns_name.labels
    }
}

impl TryFrom<&str> for DnsName {
    type Error = DnsNameError;
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        DnsName::from_name(name)
    }
}

impl TryFrom<String> for DnsName {
    type Error = DnsNameError;
    fn try_from(name: String) -> Result<Self, Self::Error> {
        DnsName::from_name(name.as_str())
    }
}

/// Represents an mDNS query.
/// 
/// mDNS (Multicast DNS) queries are used to discover services and devices on a
/// local network. This struct encapsulates a single mDNS query.
#[derive(Clone, PartialEq, Debug)]
pub struct Query {
    /// The name being queried.
    /// 
    /// This is the domain name or service name that the query is trying to
    /// resolve. For example, in mDNS, it could be a service type like
    /// `_http._tcp.local`, or a specific instance of a service like
    /// `my_esp32._http._tcp.local`.
    name: DnsName,
    /// The type of the query.
    /// 
    /// This field specifies the type of DNS record being requested.
    query_type: DnsType,
    /// The class of the query.
    /// 
    /// Typically IN (Internet), which indicates the query is for Internet use.
    /// Other classes exist but are rarely used in common scenarios.
    query_class: DnsClass,
}

impl Query {
    /// Creates a new mDNS [`Query`].
    #[inline]
    #[must_use]
    pub fn new(
        name: DnsName,
        query_type: DnsType,
        query_class: DnsClass
    ) -> Self {
        Self { name, query_type, query_class }
    }

    /// Converts raw query bytes into a [`Query`] instance. 
    pub fn from_bytes(
        bytes: &[u8],
        offset: &mut usize,
    ) -> Result<Self, ParseMdnsError> {
        let mut i: usize = *offset;

        // Get the query name:
        let name = DnsName::from_wire_format(bytes, &mut i)?;

        // Get the query type and query class:
        if bytes.len() - i < 4 {
            return Err(ParseMdnsError::MalformedQuery);
        }
        let query_type = u16::from_be_bytes([bytes[i], bytes[i + 1]]).into();
        let query_class = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]).into();
        i += 4;

        // Construct and return the query:
        *offset = i;
        Ok(Self {
            name,
            query_type,
            query_class,
        })
    }

    /// Converts the [`Query`] to raw bytes.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.to_bytes_extend(&mut buffer);
        buffer
    }

    /// Extends the `buffer` with the raw bytes that form this [`Query`].
    #[inline]
    pub fn to_bytes_extend(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.name.to_wire_format());
        buffer.extend_from_slice(&Into::<[u8; 2]>::into(self.query_type));
        buffer.extend_from_slice(&Into::<[u8; 2]>::into(self.query_class));
    }

    /// Returns an immutable reference to the name being queried.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &DnsName {
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
#[derive(Clone, PartialEq, Debug)]
pub struct Response {
    /// The name associated with this response.
    name: DnsName,
    /// The type of the response.
    response_type: DnsType,
    /// The class of the response, typically IN (Internet).
    response_class: DnsClass,
    /// The time to live for this response.
    ttl: u32,
    /// The actual data of the response.
    data: Vec<u8>,
}

impl Response {
    /// Maximum length of [`Self::data`].
    pub const MAX_DATA_LENGTH: usize = u16::MAX as usize;

    /// Creates a new mDNS [`Response`].
    #[inline]
    #[must_use]
    pub fn new(
        name: DnsName,
        response_type: DnsType,
        response_class: DnsClass,
        ttl: u32,
        data: Vec<u8>,
    ) -> Self {
        assert!(data.len() <= Self::MAX_DATA_LENGTH);
        Self {
            name,
            response_type,
            response_class,
            ttl,
            data,
        }
    }

    /// Converts raw query bytes into a [`Response`] instance. 
    pub fn from_bytes(
        bytes: &[u8],
        offset: &mut usize,
    ) -> Result<Self, ParseMdnsError> {
        let mut i: usize = *offset;

        // Get the response name:
        let name = DnsName::from_wire_format(bytes, &mut i)?;

        // Get the response type, response class, and TTL:
        if bytes.len() - i < 10 {
            return Err(ParseMdnsError::MalformedResponse);
        }
        let response_type = u16::from_be_bytes([bytes[i], bytes[i + 1]]).into();
        let response_class = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]).into();
        let ttl = u32::from_be_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]]);
        let data_length = u16::from_be_bytes([bytes[i + 8], bytes[i + 9]]) as usize;
        i += 10;

        // Read the response data:
        if bytes.len() - i < data_length {
            return Err(ParseMdnsError::MalformedResponse);
        }
        let data = bytes[i..(i+data_length)].to_vec();

        // Construct and return the query:
        *offset = i;
        Ok(Self {
            name,
            response_type,
            response_class,
            ttl,
            data,
        })
    }

    /// Converts this [`Response`] into raw bytes.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.to_bytes_extend(&mut buffer);
        buffer
    }

    /// Writes the raw byte representation of this [`Response`] to the `buffer`.
    #[inline]
    pub fn to_bytes_extend(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.name.to_wire_format());
        buffer.extend_from_slice(&Into::<[u8; 2]>::into(self.response_type));
        buffer.extend_from_slice(&Into::<[u8; 2]>::into(self.response_class));
        buffer.extend_from_slice(&self.ttl.to_be_bytes());
        buffer.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&self.data);
    }

    /// Creates a new A record mDNS [`Response`].
    #[must_use]
    pub fn new_a(
        name: DnsName,
        ttl: u32,
        ipv4_bytes: Vec<u8>,
    ) -> Self {
        assert_eq!(ipv4_bytes.len(), 4);
        Self {
            name,
            response_type: DnsType::A,
            response_class: DnsClass::IN,
            ttl,
            data: ipv4_bytes,
        }
    }

    /// Creates a new AAAA record mDNS [`Response`].
    #[must_use]
    pub fn new_aaaa(
        name: DnsName,
        ttl: u32,
        ipv6_bytes: Vec<u8>,
    ) -> Self {
        assert_eq!(ipv6_bytes.len(), 16);
        Self {
            name,
            response_type: DnsType::AAAA,
            response_class: DnsClass::IN,
            ttl,
            data: ipv6_bytes,
        }
    }

    /// Creates a new SRV mDNS [`Response`].
    /// 
    /// An SRV response is a type of DNS response that specifies information
    /// about available services in a domain. This type of response is used to
    /// locate servers that provide specific services. An SRV response provides
    /// details about the target host(s) that offer the requested service,
    /// including their priority, weight, port number, and the hostname of the
    /// server.
    #[must_use]
    pub fn new_srv(
        name: DnsName,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        hostname_bytes: &[u8],
    ) -> Self {
        let mut data = Vec::new();
        data.extend(priority.to_be_bytes());
        data.extend(weight.to_be_bytes());
        data.extend(port.to_be_bytes());
        data.extend_from_slice(hostname_bytes);
        assert!(data.len() <= Self::MAX_DATA_LENGTH);
        Self {
            name,
            response_type: DnsType::SRV,
            response_class: DnsClass::IN,
            ttl,
            data,
        }
    }

    /// Returns the name associated with this response.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &DnsName {
        &self.name
    }

    /// Returns the type of the response.
    #[inline]
    #[must_use]
    pub fn response_type(&self) -> &DnsType {
        &self.response_type
    }

    /// Returns the class of the response.
    #[inline]
    #[must_use]
    pub fn response_class(&self) -> &DnsClass {
        &self.response_class
    }

    /// Returns the time to live for this response.
    #[inline]
    #[must_use]
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns the data length of this response.
    #[inline]
    #[must_use]
    pub fn data_length(&self) -> u16 {
        self.data.len() as u16
    }

    /// Returns the actual data of the response.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Sets the time to live for this response.
    #[inline]
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    /// Sets the data for this response.
    /// 
    /// # Panics
    /// This function will panic if `data.len() > Self::MAX_DATA_LENGTH`.
    #[inline]
    pub fn set_data(&mut self, data: Vec<u8>) {
        assert!(data.len() <= Self::MAX_DATA_LENGTH);
        self.data = data;
    }
}

/// Represents an mDNS packet.
#[derive(PartialEq, Debug)]
pub struct MdnsPacket {
    /// Header for the [`MdnsPacket`].
    header: MdnsHeader,
    /// The questions section of the [`MdnsPacket`].
    question_records: Vec<Query>,
    /// The answers section of the [`MdnsPacket`].
    answer_records: Vec<Response>,
    /// The authorities section of the [`MdnsPacket`].
    authority_records: Vec<Response>,
    /// The additional records section of the [`MdnsPacket`].
    additional_records: Vec<Response>,
}

impl MdnsPacket {
    /// Creates a new [`MdnsPacket`].
    /// 
    /// This allows full control over the [`MdnsPacket`] creation.
    /// 
    /// For a simpler API, prefer using either [`MdnsPacket::new_query`] or
    /// [`MdnsPacket::new_response`].
    #[inline]
    #[must_use]
    pub fn new(
        header: MdnsHeader,
        questions: Vec<Query>,
        answers: Vec<Response>,
        authorities: Vec<Response>,
        additionals: Vec<Response>,
    ) -> Self {
        Self {
            header,
            question_records: questions,
            answer_records: answers,
            authority_records: authorities,
            additional_records: additionals,
        }
    }

    /// Creates a new query [`MdnsPacket`] containing the given records.
    /// 
    /// This automatically derives the header flags for the query.
    #[must_use]
    pub fn new_with_records(
        transaction_id: u16,
        questions: Vec<Query>,
        answers: Vec<Response>,
        authorities: Vec<Response>,
        additionals: Vec<Response>,
    ) -> Self {
        let mut flags = MdnsFlags::new();
        flags.set_opcode(Opcode::Query);
        flags.set_qr(!answers.is_empty());
        flags.set_aa(!authorities.is_empty());
        let header = MdnsHeader {
            id: transaction_id,
            flags,
            total_question_records: questions.len() as u16,
            total_answer_records: answers.len() as u16,
            total_authority_records: authorities.len() as u16,
            total_additional_records: additionals.len() as u16,
        };
        Self {
            header,
            question_records: questions,
            answer_records: answers,
            authority_records: authorities,
            additional_records: additionals,
        }
    }

    /// Creates a new query [`MdnsPacket`] containing the given questions.
    /// 
    /// This automatically derives the header flags for the query.
    #[must_use]
    pub fn new_query(
        transaction_id: u16,
        questions: Vec<Query>
    ) -> Self {
        // Create the header:
        let mut flags = MdnsFlags::new();
        flags.set_opcode(Opcode::Query);
        flags.set_qr(false);
        let total_questions = questions.len() as u16;
        let header = MdnsHeader {
            id: transaction_id,
            flags,
            total_question_records: total_questions,
            total_answer_records: 0,
            total_authority_records: 0,
            total_additional_records: 0,
        };
        // Create the packet:
        Self {
            header,
            question_records: questions,
            answer_records: Vec::new(),
            authority_records: Vec::new(),
            additional_records: Vec::new(),
        }
    }

    /// Creates a new response [`MdnsPacket`] containing the given answers,
    /// authorities, and additionals.
    /// 
    /// This automatically derives the header flags for a response.
    #[must_use]
    pub fn new_response(
        transaction_id: u16,
        answers: Vec<Response>,
        authorities: Vec<Response>,
        additionals: Vec<Response>,
    ) -> Self {
        // Create header:
        let mut flags = MdnsFlags::new();
        flags.set_opcode(Opcode::Query);
        flags.set_qr(true);
        let total_answers = answers.len() as u16;
        let total_authority_records = authorities.len() as u16;
        let total_additional_records = additionals.len() as u16;
        let header = MdnsHeader {
            id: transaction_id,
            flags,
            total_question_records: 0,
            total_answer_records: total_answers,
            total_authority_records,
            total_additional_records,
        };
        // Create the packet:
        Self {
            header,
            question_records: Vec::new(),
            answer_records: answers,
            authority_records: authorities,
            additional_records: additionals,
        }
    }

    /// Returns the transaction ID of the [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn transaction_id(&self) -> u16 {
        self.header.id
    }

    /// Returns an immutable reference to the header of the [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn header(&self) -> &MdnsHeader {
        &self.header
    }

    /// Returns an immutable reference to the questions within the
    /// [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn questions(&self) -> &Vec<Query> {
        &self.question_records
    }

    /// Returns an immutable reference to the answers within the [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn answers(&self) -> &Vec<Response> {
        &self.answer_records
    }

    /// Returns an immutable reference to the authorities within the
    /// [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn authorities(&self) -> &Vec<Response> {
        &self.authority_records
    }

    /// Returns an immutable reference to the additional records within the
    /// [`MdnsPacket`].
    #[inline]
    #[must_use]
    pub fn additionals(&self) -> &Vec<Response> {
        &self.additional_records
    }

    /// Adds a new question to the [`MdnsPacket`] and updates the header.
    pub fn add_question(&mut self, question: Query) {
        self.question_records.push(question);
        self.header.total_question_records = self.question_records.len() as u16;
    }

    /// Adds a set of questions to the [`MdnsPacket`] and updates the header.
    pub fn add_questions(&mut self, questions: Vec<Query>) {
        self.question_records.extend(questions);
        self.header.total_question_records = self.question_records.len() as u16;
    }

    /// Adds a new answer to the [`MdnsPacket`] and updates the header.
    pub fn add_answer(&mut self, answer: Response) {
        self.answer_records.push(answer);
        self.header.total_answer_records = self.answer_records.len() as u16;
    }

    /// Adds a set of answers to the [`MdnsPacket`] and updates the header.
    pub fn add_answers(&mut self, answers: Vec<Response>) {
        self.answer_records.extend(answers);
        self.header.total_answer_records = self.answer_records.len() as u16;
    }

    /// Adds a new authority to the [`MdnsPacket`] and updates the header.
    pub fn add_authority(&mut self, authority: Response) {
        self.authority_records.push(authority);
        self.header.total_authority_records = self.authority_records.len() as u16;
    }

    /// Adds new authorities to the [`MdnsPacket`] and updates the header.
    pub fn add_authorities(&mut self, authorities: Vec<Response>) {
        self.authority_records.extend(authorities);
        self.header.total_authority_records = self.authority_records.len() as u16;
    }

    /// Adds a new additional record to the [`MdnsPacket`] and updates the
    /// header.
    pub fn add_additional(&mut self, additional: Response) {
        self.additional_records.push(additional);
        self.header.total_additional_records = self.additional_records.len() as u16;
    }

    /// Adds a set of additional records to the [`MdnsPacket`] and updates the
    /// header.
    pub fn add_additionals(&mut self, additionals: Vec<Response>) {
        self.additional_records.extend(additionals);
        self.header.total_additional_records = self.additional_records.len() as u16;
    }

    /// Converts the [`MdnsPacket`] into raw bytes that can be sent as a packet.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet: Vec<u8> = self.header.to_bytes().to_vec();
        fn write_queries(packet: &mut Vec<u8>, queries: &[Query]) {
            for query in queries.iter() {
                query.to_bytes_extend(packet);
            }
        }
        fn write_responses(packet: &mut Vec<u8>, responses: &[Response]) {
            for response in responses.iter() {
                response.to_bytes_extend(packet);
            }
        }
        write_queries(&mut packet, &self.question_records);
        write_responses(&mut packet, &self.answer_records);
        write_responses(&mut packet, &self.authority_records);
        write_responses(&mut packet, &self.additional_records);
        packet
    }

    /// Converts raw mDNS packet bytes into an [`MdnsPacket`].
    pub fn from_bytes(
        bytes: &[u8],
        offset: &mut usize,
    ) -> Result<Self, ParseMdnsError> {
        let mut i: usize = *offset;

        // The first thing we need to read from the mDNS packet is the header:
        let header = MdnsHeader::from_bytes(bytes, &mut i)?;

        fn read_queries(
            bytes: &[u8],
            offset: &mut usize,
            total_queries: u16,
        ) -> Result<Vec<Query>, ParseMdnsError> {
            let mut queries = Vec::with_capacity(total_queries as usize);
            for _ in 0..total_queries {
                queries.push(Query::from_bytes(bytes, offset)?);
            }
            Ok(queries)
        }

        fn read_responses(
            bytes: &[u8],
            offset: &mut usize,
            total_responses: u16,
        ) -> Result<Vec<Response>, ParseMdnsError> {
            let mut responses = Vec::with_capacity(total_responses as usize);
            for _ in 0..total_responses {
                responses.push(Response::from_bytes(bytes, offset)?);
            }
            Ok(responses)
        }

        // Now that we have the header, we know the number of question, answer,
        // authority, and addition records that the packet contains. We can now
        // read them:
        let question_records = read_queries(
            bytes,
            &mut i,
            header.total_question_records,
        )?;
        let answer_records = read_responses(
            bytes,
            &mut i,
            header.total_answer_records,
        )?;
        let authority_records = read_responses(
            bytes,
            &mut i,
            header.total_authority_records,
        )?;
        let additional_records = read_responses(
            bytes,
            &mut i,
            header.total_additional_records,
        )?;
        
        // We can now construct the mDNS packet:
        *offset = i;
        Ok(Self {
            header,
            question_records,
            answer_records,
            authority_records,
            additional_records,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mdns_flags() {
        let mut flags = MdnsFlags::new();
        assert!(!flags.qr());
        flags.set_qr(true);
        assert!(flags.qr());
        flags.set_qr(false);
        assert!(!flags.qr());

        assert_eq!(flags.opcode(), Opcode::Query);
        flags.set_opcode(Opcode::IQuery);
        assert_eq!(flags.opcode(), Opcode::IQuery);
        flags.set_opcode(Opcode::Status);
        assert_eq!(flags.opcode(), Opcode::Status);
        flags.set_opcode(Opcode::Unknown(9));
        assert_eq!(flags.opcode(), Opcode::Unknown(9));

        assert!(!flags.aa());
        flags.set_aa(true);
        assert!(flags.aa());
        flags.set_aa(false);
        assert!(!flags.aa());

        assert!(!flags.tc());
        flags.set_tc(true);
        assert!(flags.tc());
        flags.set_tc(false);
        assert!(!flags.tc());

        assert!(!flags.rd());
        flags.set_rd(true);
        assert!(flags.rd());
        flags.set_rd(false);
        assert!(!flags.rd());

        assert!(!flags.ra());
        flags.set_ra(true);
        assert!(flags.ra());
        flags.set_ra(false);
        assert!(!flags.ra());

        assert_eq!(flags.rcode(), Rcode::NoError);
        flags.set_rcode(Rcode::FormatError);
        assert_eq!(flags.rcode(), Rcode::FormatError);
        flags.set_rcode(Rcode::ServerFailure);
        assert_eq!(flags.rcode(), Rcode::ServerFailure);
        flags.set_rcode(Rcode::NameError);
        assert_eq!(flags.rcode(), Rcode::NameError);
        flags.set_rcode(Rcode::NotImplemented);
        assert_eq!(flags.rcode(), Rcode::NotImplemented);
        flags.set_rcode(Rcode::Refused);
        assert_eq!(flags.rcode(), Rcode::Refused);
        flags.set_rcode(Rcode::Unknown(7));
        assert_eq!(flags.rcode(), Rcode::Unknown(7));
    }

    #[test]
    fn test_mdns_flags_from_u16() {
        let flags = MdnsFlags::from(0x8000);
        assert!(flags.qr());
        let flags: u16 = flags.into();
        assert_eq!(flags, 0x8000);
    }

    #[test]
    fn test_mdns_header() {
        let header = MdnsHeader {
            id: 1234,
            flags: MdnsFlags::new(),
            total_question_records: 1,
            total_answer_records: 2,
            total_authority_records: 3,
            total_additional_records: 4,
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes, [
            0x04, 0xd2, // ID
            0x00, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x02, // ANCOUNT
            0x00, 0x03, // NSCOUNT
            0x00, 0x04, // ARCOUNT
        ]);
    }

    #[test]
    fn test_dns_type() {
        assert_eq!(DnsType::from(0x0001), DnsType::A);
        assert_eq!(u16::from(DnsType::A), 0x0001);
        assert_eq!(<[u8; 2]>::from(DnsType::A), [0x00, 0x01]);
        assert_eq!(DnsType::from([0x00, 0x01]), DnsType::A);
    }

    #[test]
    fn test_dns_class() {
        assert_eq!(DnsClass::from(0x0001), DnsClass::IN);
        assert_eq!(u16::from(DnsClass::IN), 0x0001);
        assert_eq!(<[u8; 2]>::from(DnsClass::IN), [0x00, 0x01]);
        assert_eq!(DnsClass::from([0x00, 0x01]), DnsClass::IN);
    }

    #[test]
    fn test_query() {
        let query = Query::new(
            DnsName::from_name("my_sensor._http._tcp.local.").unwrap(),
            DnsType::A,
            DnsClass::IN,
        );
        assert_eq!(query.name().to_string(), "my_sensor._http._tcp.local.");
        assert_eq!(query.query_type(), DnsType::A);
        assert_eq!(query.query_class(), DnsClass::IN);
    }

    #[test]
    fn test_response() {
        let mut response = Response::new(
            DnsName::from_name("my_sensor._http._tcp.local.").unwrap(),
            DnsType::A,
            DnsClass::IN,
            120,
            vec![127, 0, 0, 1],
        );

        assert_eq!(response.name().to_string(), "my_sensor._http._tcp.local.");
        assert_eq!(response.response_type(), &DnsType::A);
        assert_eq!(response.response_class(), &DnsClass::IN);
        assert_eq!(response.ttl(), 120);
        assert_eq!(response.data_length(), 4);
        assert_eq!(response.data(), &vec![127, 0, 0, 1]);

        response.set_ttl(240);
        assert_eq!(response.ttl(), 240);

        response.set_data(vec![192, 168, 0, 1]);
        assert_eq!(response.data_length(), 4);
        assert_eq!(response.data(), &vec![192, 168, 0, 1]);
    }

    #[test]
    fn test_mdns_packet() {
        let header = MdnsHeader {
            id: 1234,
            flags: MdnsFlags::new(),
            total_question_records: 0,
            total_answer_records: 0,
            total_authority_records: 0,
            total_additional_records: 0,
        };

        let mut packet = MdnsPacket::new(
            header,
            vec![],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(packet.transaction_id(), 1234);
        assert_eq!(packet.header(), &header);
        assert_eq!(packet.questions().len(), 0);
        assert_eq!(packet.answers().len(), 0);
        assert_eq!(packet.authorities().len(), 0);
        assert_eq!(packet.additionals().len(), 0);

        let question = Query::new(
            DnsName::from_name("my_sensor._http._tcp.local.").unwrap(),
            DnsType::A,
            DnsClass::IN,
        );

        packet.add_question(question.clone());
        assert_eq!(packet.questions().len(), 1);
        assert_eq!(packet.questions()[0], question);

        let response = Response::new(
            DnsName::from_name("my_sensor._http._tcp.local.").unwrap(),
            DnsType::A,
            DnsClass::IN,
            120,
            vec![127, 0, 0, 1],
        );

        packet.add_answer(response.clone());
        assert_eq!(packet.answers().len(), 1);
        assert_eq!(packet.answers()[0], response);

        packet.add_authority(response.clone());
        assert_eq!(packet.authorities().len(), 1);
        assert_eq!(packet.authorities()[0], response);

        packet.add_additional(response.clone());
        assert_eq!(packet.additionals().len(), 1);
        assert_eq!(packet.additionals()[0], response);
    }

    #[test]
    fn test_mdns_packet_to_bytes() {
        let header = MdnsHeader {
            id: 1234,
            flags: MdnsFlags::new(),
            total_question_records: 0,
            total_answer_records: 0,
            total_authority_records: 0,
            total_additional_records: 0,
        };
        let packet = MdnsPacket::new(header, vec![], vec![], vec![], vec![]);
        assert_eq!(packet.to_bytes(), vec![
            0x04, 0xd2, // ID
            0x00, 0x00, // Flags
            0x00, 0x00, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ]);
    }

    #[test]
    fn test_create_dns_name_from_str() {
        let dns_name = DnsName::from_name("example_service._http._tcp.local.").unwrap();
        assert_eq!(dns_name.labels, vec!["example_service", "_http", "_tcp", "local"]);
    }

    #[test]
    fn test_create_dns_name_from_invalid_str() {
        let err = DnsName::from_name("example_service._http._tcp.local").unwrap_err();
        assert_eq!(err, DnsNameError::MustEndWithDot);
    }

    #[test]
    fn test_create_dns_name_from_str_with_long_label() {
        let mut label = "a".repeat(64);
        label.push('.');
        let err = DnsName::from_name(label.as_str()).unwrap_err();
        assert_eq!(err, DnsNameError::LabelTooLong);
    }

    #[test]
    fn test_to_wire_format() {
        let dns_name = DnsName::from_name("example_service._http._tcp.local.").unwrap();
        let wire_format = dns_name.to_wire_format();
        assert_eq!(wire_format, vec![
            15, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e',
            5, b'_', b'h', b't', b't', b'p',
            4, b'_', b't', b'c', b'p',
            5, b'l', b'o', b'c', b'a', b'l',
            0
        ]);
    }

    #[test]
    fn test_from_wire_format() {
        let wire_format = vec![
            15, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e',
            5, b'_', b'h', b't', b't', b'p',
            4, b'_', b't', b'c', b'p',
            5, b'l', b'o', b'c', b'a', b'l',
            0
        ];
        let mut offset = 0;
        let dns_name = DnsName::from_wire_format(&wire_format, &mut offset).unwrap();
        assert_eq!(dns_name.labels, vec!["example_service", "_http", "_tcp", "local"]);
        assert_eq!(offset, wire_format.len());
    }

    #[test]
    fn test_from_invalid_wire_format() {
        let wire_format = vec![
            15, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e',
            5, b'_', b'h', b't', b't', b'p',
            4, b'_', b't', b'c', b'p',
            5, b'l', b'o', b'c', b'a', b'l',
        ];
        let err = DnsName::from_wire_format(&wire_format, &mut 0).unwrap_err();
        assert_eq!(err, ParseMdnsError::InvalidEndOfLabels);
    }

    #[test]
    fn test_header_from_bytes() {
        let header_a = MdnsHeader {
            id: 1234,
            flags: MdnsFlags::from_bytes([0x84, 0x21]),
            total_question_records: 10,
            total_answer_records: 11,
            total_authority_records: 12,
            total_additional_records: 13,
        };
        let header_b = MdnsHeader::from_bytes(
            &header_a.to_bytes(),
            &mut 0,
        ).unwrap();
        assert_eq!(header_a, header_b);
    }

    #[test]
    fn test_query_from_bytes() {
        let query_a = Query::new(
            DnsName::from_name("test_service._http._tcp.local.").unwrap(),
            DnsType::PTR,
            DnsClass::IN,
        );
        let query_b = Query::from_bytes(
            &query_a.to_bytes(),
            &mut 0,
        ).expect("Failed to convert `query_a` to `query_b`");
        assert_eq!(query_a, query_b);
    }

    #[test]
    fn test_response_from_bytes() {
        let response_a = Response::new(
            DnsName::from_name("test_service._http._tcp.local.").unwrap(),
            DnsType::PTR,
            DnsClass::IN,
            120,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        );
        let response_b = Response::from_bytes(
            &response_a.to_bytes(),
            &mut 0,
        ).expect("Failed to convert `response_a` to `response_b`");
        assert_eq!(response_a, response_b);
    }

    #[test]
    fn test_packet_from_bytes() {
        fn test_from_bytes(packet: MdnsPacket) {
            let from_bytes = MdnsPacket::from_bytes(
                &packet.to_bytes(),
                &mut 0,
            ).expect("Failed to convert raw packet bytes into a new packet");
            assert_eq!(from_bytes, packet);
        }
        // Test query packet:
        test_from_bytes(MdnsPacket::new_query(1234, vec![
            Query::new(
                DnsName::from_name("test_service._http._tcp.local.").unwrap(),
                DnsType::PTR,
                DnsClass::IN,
            ),
        ]));
        // Test response packet:
        test_from_bytes(
            MdnsPacket::new_response(
                1234,
                vec![
                        Response::new(
                        DnsName::from_name("test_service._http._tcp.local.").unwrap(),
                        DnsType::PTR,
                        DnsClass::IN,
                        120,
                        vec![127, 0, 0, 1],
                    )
                ],
                vec![
                        Response::new(
                        DnsName::from_name("test_service._http._tcp.local.").unwrap(),
                        DnsType::PTR,
                        DnsClass::IN,
                        300,
                        Vec::new(),
                    )
                ],
                vec![
                        Response::new(
                        DnsName::from_name("test_service._http._tcp.local.").unwrap(),
                        DnsType::PTR,
                        DnsClass::IN,
                        600,
                        vec![0, 1, 2, 3, 4, 5, 6, 7],
                    )
                ],
            )
        );
    }
}