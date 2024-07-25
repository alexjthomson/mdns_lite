/// Describes the `RCODE` field in [`MdnsFlags`](super::MdnsFlags).
/// 
/// This indicates the result of a query.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum MdnsRcode {
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

impl From<u8> for MdnsRcode {
    #[inline]
    #[must_use]
    fn from(rcode_id: u8) -> Self {
        match rcode_id {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            unknown => Self::Unknown(unknown),
        }
    }
}

impl From<MdnsRcode> for u8 {
    #[inline]
    #[must_use]
    fn from(rcode: MdnsRcode) -> Self {
        match rcode {
            MdnsRcode::NoError => 0,
            MdnsRcode::FormatError => 1,
            MdnsRcode::ServerFailure => 2,
            MdnsRcode::NameError => 3,
            MdnsRcode::NotImplemented => 4,
            MdnsRcode::Refused => 5,
            MdnsRcode::Unknown(unknown) => unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rcode_from_u16() {
        assert_eq!(MdnsRcode::from(0x00), MdnsRcode::NoError);
        assert_eq!(MdnsRcode::from(0x01), MdnsRcode::FormatError);
        assert_eq!(MdnsRcode::from(0x02), MdnsRcode::ServerFailure);
        assert_eq!(MdnsRcode::from(0x03), MdnsRcode::NameError);
        assert_eq!(MdnsRcode::from(0x04), MdnsRcode::NotImplemented);
        assert_eq!(MdnsRcode::from(0x05), MdnsRcode::Refused);
        assert_eq!(MdnsRcode::from(0xff), MdnsRcode::Unknown(0xff));
    }

    #[test]
    fn test_u16_from_rcode() {
        assert_eq!(u8::from(MdnsRcode::NoError), 0x00);
        assert_eq!(u8::from(MdnsRcode::FormatError), 0x01);
        assert_eq!(u8::from(MdnsRcode::ServerFailure), 0x02);
        assert_eq!(u8::from(MdnsRcode::NameError), 0x03);
        assert_eq!(u8::from(MdnsRcode::NotImplemented), 0x04);
        assert_eq!(u8::from(MdnsRcode::Refused), 0x05);
        assert_eq!(u8::from(MdnsRcode::Unknown(0xff)), 0xff);
    }
}