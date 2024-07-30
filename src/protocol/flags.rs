use super::{
    MdnsOpcode,
    MdnsRcode,
};

/// Represents the flags in an [`MdnsHeader`].
/// 
/// This struct allows structured access to the individual bits and sub-fields
/// within the 16-bit flags field.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct MdnsFlags(pub(super) u16);

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
    pub const fn empty() -> Self {
        Self(0)
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
    pub fn opcode(&self) -> MdnsOpcode {
        MdnsOpcode::from(((self.0 & Self::OPCODE_MASK) >> 11) as u8)
    }

    /// Sets the OPCODE field.
    #[inline]
    pub fn set_opcode(&mut self, opcode: MdnsOpcode) {
        self.0 = (self.0 & !Self::OPCODE_MASK) | ((u8::from(opcode) as u16 & 0x0f) << 11);
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
    #[must_use]
    pub fn rcode(&self) -> MdnsRcode {
        MdnsRcode::from((self.0 & Self::RCODE_MASK) as u8)
    }

    /// Sets the RCODE (Response Code) field.
    pub fn set_rcode(&mut self, rcode: MdnsRcode) {
        self.0 = (self.0 & !Self::RCODE_MASK) | (u8::from(rcode) as u16);
    }
}

impl From<MdnsFlags> for u16 {
    #[inline]
    #[must_use]
    fn from(flags: MdnsFlags) -> Self {
        flags.0
    }
}

impl From<u16> for MdnsFlags {
    #[inline]
    #[must_use]
    fn from(flags: u16) -> Self {
        Self(flags)
    }
}

impl From<MdnsFlags> for [u8; 2] {
    #[inline]
    #[must_use]
    fn from(flags: MdnsFlags) -> Self {
        u16::to_be_bytes(flags.0)
    }
}

impl From<[u8; 2]> for MdnsFlags {
    #[inline]
    #[must_use]
    fn from(slice: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensures that [`MdnsFlags::empty`] returns an empty set of flags.
    #[test]
    fn test_empty_flags() {
        let flags: MdnsFlags = MdnsFlags::empty();
        assert!(!flags.qr());
        assert_eq!(flags.opcode(), MdnsOpcode::Query);
        assert!(!flags.aa());
        assert!(!flags.tc());
        assert!(!flags.rd());
        assert!(!flags.ra());
        assert_eq!(flags.rcode(), MdnsRcode::NoError);
    }

    /// Validates that the [`MdnsFlags`] QR bit can be set correctly.
    #[test]
    fn test_flags_qr() {
        let mut flags: MdnsFlags = MdnsFlags::empty();
        assert!(!flags.qr());
        flags.set_qr(true);
        assert!(flags.qr());
        flags.set_qr(false);
        assert!(!flags.qr());
    }

    /// Validates that the [`MdnsFlags`] opcode bits can be set correctly.
    #[test]
    fn test_flags_opcode() {
        let mut flags: MdnsFlags = MdnsFlags::empty();
        assert_eq!(flags.opcode(), MdnsOpcode::Query);
        flags.set_opcode(MdnsOpcode::Query);
        assert_eq!(flags.opcode(), MdnsOpcode::Query);
        flags.set_opcode(MdnsOpcode::IQuery);
        assert_eq!(flags.opcode(), MdnsOpcode::IQuery);
        flags.set_opcode(MdnsOpcode::Status);
        assert_eq!(flags.opcode(), MdnsOpcode::Status);
        flags.set_opcode(MdnsOpcode::Unknown(15));
        assert_eq!(flags.opcode(), MdnsOpcode::Unknown(15));
    }

    /// Validates that the [`MdnsFlags`] aa bit can be set correctly.
    #[test]
    fn test_flags_aa() {
        let mut flags: MdnsFlags = MdnsFlags::empty();
        assert!(!flags.aa());
        flags.set_aa(true);
        assert!(flags.aa());
        flags.set_aa(false);
        assert!(!flags.aa());
    }

    /// Validates that the [`MdnsFlags`] tc bit can be set correctly.
    #[test]
    fn test_flags_tc() {
        let mut flags: MdnsFlags = MdnsFlags::empty();
        assert!(!flags.tc());
        flags.set_tc(true);
        assert!(flags.tc());
        flags.set_tc(false);
        assert!(!flags.tc());
    }

    /// Validates that the [`MdnsFlags`] rd bit can be set correctly.
    #[test]
    fn test_flags_rd() {
        let mut flags: MdnsFlags = MdnsFlags::empty();
        assert!(!flags.rd());
        flags.set_rd(true);
        assert!(flags.rd());
        flags.set_rd(false);
        assert!(!flags.rd());
    }

    /// Validates that the [`MdnsFlags`] ra bit can be set correctly.
    #[test]
    fn test_flags_ra() {
        let mut flags: MdnsFlags = MdnsFlags::empty();
        assert!(!flags.ra());
        flags.set_ra(true);
        assert!(flags.ra());
        flags.set_ra(false);
        assert!(!flags.ra());
    }

    /// Validates that the [`MdnsFlags`] rcode bit can be set correctly.
    #[test]
    fn test_flags_rcode() {
        let mut flags: MdnsFlags = MdnsFlags::empty();
        assert_eq!(flags.rcode(), MdnsRcode::NoError);
        flags.set_rcode(MdnsRcode::NoError);
        assert_eq!(flags.rcode(), MdnsRcode::NoError);
        flags.set_rcode(MdnsRcode::FormatError);
        assert_eq!(flags.rcode(), MdnsRcode::FormatError);
        flags.set_rcode(MdnsRcode::ServerFailure);
        assert_eq!(flags.rcode(), MdnsRcode::ServerFailure);
        flags.set_rcode(MdnsRcode::NameError);
        assert_eq!(flags.rcode(), MdnsRcode::NameError);
        flags.set_rcode(MdnsRcode::NotImplemented);
        assert_eq!(flags.rcode(), MdnsRcode::NotImplemented);
        flags.set_rcode(MdnsRcode::Refused);
        assert_eq!(flags.rcode(), MdnsRcode::Refused);
        flags.set_rcode(MdnsRcode::Unknown(15));
        assert_eq!(flags.rcode(), MdnsRcode::Unknown(15));
    }

    /// Creates and mutates an [`MdnsFlags`] instance in multiple different
    /// ways, ensuring none of the bitwise operations affect other values.
    #[test]
    fn test_flags_generic() {
        let mut flags = MdnsFlags::empty();
        assert!(!flags.qr());
        flags.set_qr(true);
        assert!(flags.qr());
        flags.set_qr(false);
        assert!(!flags.qr());

        assert_eq!(flags.opcode(), MdnsOpcode::Query);
        flags.set_opcode(MdnsOpcode::IQuery);
        assert_eq!(flags.opcode(), MdnsOpcode::IQuery);
        flags.set_opcode(MdnsOpcode::Status);
        assert_eq!(flags.opcode(), MdnsOpcode::Status);
        flags.set_opcode(MdnsOpcode::Unknown(9));
        assert_eq!(flags.opcode(), MdnsOpcode::Unknown(9));

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

        assert_eq!(flags.rcode(), MdnsRcode::NoError);
        flags.set_rcode(MdnsRcode::FormatError);
        assert_eq!(flags.rcode(), MdnsRcode::FormatError);
        flags.set_rcode(MdnsRcode::ServerFailure);
        assert_eq!(flags.rcode(), MdnsRcode::ServerFailure);
        flags.set_rcode(MdnsRcode::NameError);
        assert_eq!(flags.rcode(), MdnsRcode::NameError);
        flags.set_rcode(MdnsRcode::NotImplemented);
        assert_eq!(flags.rcode(), MdnsRcode::NotImplemented);
        flags.set_rcode(MdnsRcode::Refused);
        assert_eq!(flags.rcode(), MdnsRcode::Refused);
        flags.set_rcode(MdnsRcode::Unknown(7));
        assert_eq!(flags.rcode(), MdnsRcode::Unknown(7));
    }

    #[test]
    fn test_u16_from_flags() {
        let mut flags: MdnsFlags = MdnsFlags::empty();
        assert_eq!(Into::<u16>::into(flags), 0x0000);

        flags.set_qr(true);
        assert_eq!(Into::<u16>::into(flags), MdnsFlags::QR_MASK);

        flags.set_qr(false);
        flags.set_aa(true);
        assert_eq!(Into::<u16>::into(flags), MdnsFlags::AA_MASK);

        flags.set_qr(true);
        assert_eq!(Into::<u16>::into(flags), MdnsFlags::AA_MASK | MdnsFlags::QR_MASK);
    }

    #[test]
    fn test_flags_from_u16() {
        let flags: MdnsFlags = MdnsFlags::from(MdnsFlags::QR_MASK);
        assert!(flags.qr());
    }

    #[test]
    fn test_slice_from_flags() {
        let mut flags: MdnsFlags = MdnsFlags::empty();
        assert_eq!(Into::<[u8; 2]>::into(flags), [0x00, 0x00]);

        flags.set_qr(true);
        assert_eq!(Into::<[u8; 2]>::into(flags), [0x80, 0x00]);

        flags.set_qr(false);
        flags.set_aa(true);
        assert_eq!(Into::<[u8; 2]>::into(flags), [0x04, 0x00]);

        flags.set_qr(true);
        assert_eq!(Into::<[u8; 2]>::into(flags), [0x84, 0x00]);
    }

    #[test]
    fn test_flags_from_slice() {
        let flags: MdnsFlags = MdnsFlags::from([0x84, 0x80]);
        assert!(flags.qr());
        assert_eq!(flags.opcode(), MdnsOpcode::Query);
        assert!(flags.aa());
        assert!(!flags.tc());
        assert!(!flags.rd());
        assert!(flags.ra());
        assert_eq!(flags.rcode(), MdnsRcode::NoError);
    }
}