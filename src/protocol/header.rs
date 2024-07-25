use super::{
    flags::MdnsFlags,
    MdnsParseError,
};

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
/// The total size of an mDNS header is 12 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
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

    /// Creates a new [`MdnsHeader`].
    #[inline]
    #[must_use]
    pub fn new(
        id: u16,
        flags: MdnsFlags,
        total_question_records: u16,
        total_answer_records: u16,
        total_authority_records: u16,
        total_additional_records: u16,
    ) -> Self {
        Self {
            id,
            flags,
            total_question_records,
            total_answer_records,
            total_authority_records,
            total_additional_records,
        }
    }

    /// Creates a new empty [`MdnsHeader`].
    /// 
    /// An empty header is characterised by:
    /// - Empty [`MdnsFlags`].
    /// - Zero total records.
    #[inline]
    #[must_use]
    pub fn new_empty(id: u16) -> Self {
        Self {
            id,
            flags: MdnsFlags::empty(),
            total_question_records: 0,
            total_answer_records: 0,
            total_authority_records: 0,
            total_additional_records: 0,
        }
    }

    /// Returns the ID of the transaction that the [`MdnsHeader`] belongs to.
    #[inline]
    #[must_use]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Overwrites the transaction ID of the [`MdnsHeader`].
    #[inline]
    pub fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    /// Returns the [`MdnsFlags`].
    #[inline]
    #[must_use]
    pub fn flags(&self) -> MdnsFlags {
        self.flags
    }

    /// Overwrites the [`MdnsFlags`].
    #[inline]
    pub fn set_flags(&mut self, flags: MdnsFlags) {
        self.flags = flags
    }

    /// Returns the total number of question records that the packet is expected
    /// to contain.
    /// 
    /// This must match the actual number of question records included in the
    /// packet.
    #[inline]
    #[must_use]
    pub fn total_question_records(&self) -> u16 {
        self.total_question_records
    }

    /// Overwrites the total number of question records that the packet is
    /// expected to contain.
    /// 
    /// This must match the actual number of question records included in the
    /// packet.
    #[inline]
    pub(super) fn set_total_question_records(
        &mut self,
        total_question_records: u16
    ) {
        self.total_question_records = total_question_records
    }

    /// Returns the total number of answer records that the packet is expected
    /// to contain.
    /// 
    /// This must match the actual number of answer records included in the
    /// packet.
    #[inline]
    #[must_use]
    pub fn total_answer_records(&self) -> u16 {
        self.total_answer_records
    }

    /// Overwrites the total number of answer records that the packet is
    /// expected to contain.
    /// 
    /// This must match the actual number of answer records included in the
    /// packet.
    #[inline]
    pub(super) fn set_total_answer_records(
        &mut self,
        total_answer_records: u16
    ) {
        self.total_question_records = total_answer_records
    }

    /// Returns the total number of authority records that the packet is
    /// expected to contain.
    /// 
    /// This must match the actual number of authority records included in the
    /// packet.
    #[inline]
    #[must_use]
    pub fn total_authority_records(&self) -> u16 {
        self.total_authority_records
    }

    /// Overwrites the total number of authority records that the packet is
    /// expected to contain.
    /// 
    /// This must match the actual number of authority records included in the
    /// packet.
    #[inline]
    pub(super) fn set_total_authority_records(
        &mut self,
        total_authority_records: u16
    ) {
        self.total_question_records = total_authority_records
    }

    /// Returns the total number of additional records that the packet is
    /// expected to contain.
    /// 
    /// This must match the actual number of additional records included in the
    /// packet.
    #[inline]
    #[must_use]
    pub fn total_additional_records(&self) -> u16 {
        self.total_additional_records
    }

    /// Overwrites the total number of additional records that the packet is
    /// expected to contain.
    /// 
    /// This must match the actual number of additional records included in the
    /// packet.
    #[inline]
    pub(super) fn set_total_additional_records(
        &mut self,
        total_additional_records: u16
    ) {
        self.total_question_records = total_additional_records
    }

    /// Converts the [`MdnsHeader`] into raw bytes that can form the start of an
    /// mDNS packet.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::MDNS_HEADER_SIZE] {
        let flags: u16 = self.flags.into();
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
    pub fn from_bytes(bytes: &[u8], offset: &mut usize) -> Result<Self, MdnsParseError> {
        // Get the mDNS header bytes from the `bytes` slice passed into the
        // function:
        if bytes.len() - *offset < Self::MDNS_HEADER_SIZE {
            return Err(MdnsParseError::HeaderTooSmall);
        }
        let header: &[u8; Self::MDNS_HEADER_SIZE] = &bytes[*offset..(*offset + Self::MDNS_HEADER_SIZE)]
            .try_into()
            .unwrap();

        // Apply the offset and return the header:
        *offset += Self::MDNS_HEADER_SIZE;
        Ok(Self {
            id: u16::from_be_bytes([header[0], header[1]]),
            flags: MdnsFlags::from([header[2], header[3]]),
            total_question_records: u16::from_be_bytes([header[4], header[5]]),
            total_answer_records: u16::from_be_bytes([header[6], header[7]]),
            total_authority_records: u16::from_be_bytes([header[8], header[9]]),
            total_additional_records: u16::from_be_bytes([header[10], header[11]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Achieve 100% test coverage.

    #[test]
    fn test_new_header() {
        let header: MdnsHeader = MdnsHeader::new(1234, MdnsFlags::empty(), 1, 2, 3, 4);
        assert_eq!(header.id(), 1234);
        assert_eq!(header.flags(), MdnsFlags::empty());
        assert_eq!(header.total_question_records(), 1);
        assert_eq!(header.total_answer_records(), 2);
        assert_eq!(header.total_authority_records(), 3);
        assert_eq!(header.total_additional_records(), 4);
    }

    #[test]
    fn test_header_to_bytes() {
        let header: MdnsHeader = MdnsHeader::new(1234, MdnsFlags::empty(), 1, 2, 3, 4);
        let bytes: [u8; 12] = header.to_bytes();
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
    fn test_header_from_bytes() {
        // Validate that an mDNS header can be converted to bytes and then
        // converted back into an mDNS header:
        let header_a: MdnsHeader = MdnsHeader {
            id: 1234,
            flags: MdnsFlags::from(0x8421),
            total_question_records: 10,
            total_answer_records: 11,
            total_authority_records: 12,
            total_additional_records: 13,
        };
        let mut offset: usize = 0;
        let header_b: MdnsHeader = MdnsHeader::from_bytes(
            &header_a.to_bytes(),
            &mut offset,
        ).expect("Failed to convert `header_a` into `header_b`");
        assert_eq!(header_a, header_b);

        // We should check that the offset is correct. mDNS headers are always
        // 12 bytes so this should be easy:
        assert_eq!(offset, 12);
    }
}