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

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Add unit tests.
}