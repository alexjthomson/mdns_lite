/// Describes the `OPCODE` field in [`MdnsFlags`](super::MdnsFlags).
/// 
/// This field indicates the kind of query contained within an
/// [`MdnsPacket`](super::MdnsPacket). Values are defined according to the DNS
/// protocol specifications.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum MdnsOpcode {
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

impl From<u8> for MdnsOpcode {
    #[inline]
    #[must_use]
    fn from(opcode_id: u8) -> Self {
        match opcode_id {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            unknown => Self::Unknown(unknown),
        }
    }
}

impl From<MdnsOpcode> for u8 {
    #[inline]
    #[must_use]
    fn from(opcode: MdnsOpcode) -> Self {
        match opcode {
            MdnsOpcode::Query => 0,
            MdnsOpcode::IQuery => 1,
            MdnsOpcode::Status => 2,
            MdnsOpcode::Unknown(unknown) => unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_from_u16() {
        assert_eq!(MdnsOpcode::from(0x00), MdnsOpcode::Query);
        assert_eq!(MdnsOpcode::from(0x01), MdnsOpcode::IQuery);
        assert_eq!(MdnsOpcode::from(0x02), MdnsOpcode::Status);
        assert_eq!(MdnsOpcode::from(0xff), MdnsOpcode::Unknown(0xff));
    }

    #[test]
    fn test_u16_from_opcode() {
        assert_eq!(u8::from(MdnsOpcode::Query), 0x00);
        assert_eq!(u8::from(MdnsOpcode::IQuery), 0x01);
        assert_eq!(u8::from(MdnsOpcode::Status), 0x02);
        assert_eq!(u8::from(MdnsOpcode::Unknown(0xff)), 0xff);
    }
}