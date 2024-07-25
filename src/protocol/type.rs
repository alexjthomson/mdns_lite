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

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Achieve 100% test coverage.

    #[test]
    fn test_dns_type() {
        assert_eq!(DnsType::from(0x0001), DnsType::A);
        assert_eq!(u16::from(DnsType::A), 0x0001);
        assert_eq!(<[u8; 2]>::from(DnsType::A), [0x00, 0x01]);
        assert_eq!(DnsType::from([0x00, 0x01]), DnsType::A);
    }
}