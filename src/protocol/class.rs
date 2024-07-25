/// Represents the DNS classes in mDNS.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum MdnsClass {
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

impl From<u16> for MdnsClass {
    #[must_use]
    fn from(class_id: u16) -> Self {
        match class_id {
            0x0001 => Self::IN,
            0x0003 => Self::CH,
            0x0004 => Self::HS,
            0x00ff => Self::ANY,
            _ => Self::Unknown(class_id),
        }
    }
}

impl From<MdnsClass> for u16 {
    #[must_use]
    fn from(class: MdnsClass) -> Self {
        match class {
            MdnsClass::IN  => 0x0001,
            MdnsClass::CH  => 0x0003,
            MdnsClass::HS  => 0x0004,
            MdnsClass::ANY => 0x00ff,
            MdnsClass::Unknown(id) => id,
        }
    }
}

impl From<[u8; 2]> for MdnsClass {
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

impl From<MdnsClass> for [u8; 2] {
    #[must_use]
    fn from(class: MdnsClass) -> Self {
        match class {
            MdnsClass::IN  => [0x00, 0x01],
            MdnsClass::CH  => [0x00, 0x03],
            MdnsClass::HS  => [0x00, 0x04],
            MdnsClass::ANY => [0x00, 0xff],
            MdnsClass::Unknown(id) => [(id >> 8) as u8, (id & 0xff) as u8],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_from_u16() {
        assert_eq!(MdnsClass::from(0x0001), MdnsClass::IN);
        assert_eq!(MdnsClass::from(0x0003), MdnsClass::CH);
        assert_eq!(MdnsClass::from(0x0004), MdnsClass::HS);
        assert_eq!(MdnsClass::from(0x00ff), MdnsClass::ANY);
        assert_eq!(MdnsClass::from(0x1234), MdnsClass::Unknown(0x1234));
    }

    #[test]
    fn test_u16_from_class() {
        assert_eq!(u16::from(MdnsClass::IN), 0x0001);
        assert_eq!(u16::from(MdnsClass::CH), 0x0003);
        assert_eq!(u16::from(MdnsClass::HS), 0x0004);
        assert_eq!(u16::from(MdnsClass::ANY), 0x00ff);
        assert_eq!(u16::from(MdnsClass::Unknown(0x1234)), 0x1234);
    }

    #[test]
    fn test_class_from_slice() {
        assert_eq!(MdnsClass::from([0x00, 0x01]), MdnsClass::IN);
        assert_eq!(MdnsClass::from([0x00, 0x03]), MdnsClass::CH);
        assert_eq!(MdnsClass::from([0x00, 0x04]), MdnsClass::HS);
        assert_eq!(MdnsClass::from([0x00, 0xff]), MdnsClass::ANY);
        assert_eq!(MdnsClass::from([0x12, 0x34]), MdnsClass::Unknown(0x1234));
    }

    #[test]
    fn test_slice_from_class() {
        assert_eq!(<[u8; 2]>::from(MdnsClass::IN), [0x00, 0x01]);
        assert_eq!(<[u8; 2]>::from(MdnsClass::CH), [0x00, 0x03]);
        assert_eq!(<[u8; 2]>::from(MdnsClass::HS), [0x00, 0x04]);
        assert_eq!(<[u8; 2]>::from(MdnsClass::ANY), [0x00, 0xff]);
        assert_eq!(<[u8; 2]>::from(MdnsClass::Unknown(0x1234)), [0x12, 0x34]);
    }
}