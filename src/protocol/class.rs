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

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Achieve 100% test coverage.

    #[test]
    fn test_dns_class() {
        assert_eq!(DnsClass::from(0x0001), DnsClass::IN);
        assert_eq!(u16::from(DnsClass::IN), 0x0001);
        assert_eq!(<[u8; 2]>::from(DnsClass::IN), [0x00, 0x01]);
        assert_eq!(DnsClass::from([0x00, 0x01]), DnsClass::IN);
    }
}