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

#[cfg(test)]
mod tests {
    use super::*;
    
    // TODO: Add unit tests.
}