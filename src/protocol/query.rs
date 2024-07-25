use super::{
    MdnsClass,
    MdnsName,
    MdnsType,
    MdnsParseError,
};

/// Represents an mDNS query.
/// 
/// mDNS (Multicast DNS) queries are used to discover services and devices on a
/// local network. This struct encapsulates a single mDNS query.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct MdnsQuery {
    /// The name being queried.
    /// 
    /// This is the domain name or service name that the query is trying to
    /// resolve. For example, in mDNS, it could be a service type like
    /// `_http._tcp.local`, or a specific instance of a service like
    /// `my_esp32._http._tcp.local`.
    name: MdnsName,
    /// The type of the query.
    /// 
    /// This field specifies the type of DNS record being requested.
    query_type: MdnsType,
    /// The class of the query.
    /// 
    /// Typically IN (Internet), which indicates the query is for Internet use.
    /// Other classes exist but are rarely used in common scenarios.
    query_class: MdnsClass,
}

impl MdnsQuery {
    /// Creates a new mDNS [`MdnsQuery`].
    #[inline]
    #[must_use]
    pub fn new(
        name: MdnsName,
        query_type: MdnsType,
        query_class: MdnsClass
    ) -> Self {
        Self { name, query_type, query_class }
    }

    /// Converts raw query bytes into a [`MdnsQuery`] instance. 
    pub fn from_bytes(
        bytes: &[u8],
        offset: &mut usize,
    ) -> Result<Self, MdnsParseError> {
        let mut i: usize = *offset;

        // Get the query name:
        let name = MdnsName::from_wire_format(bytes, &mut i)?;

        // Get the query type and query class:
        if bytes.len() - i < 4 {
            return Err(MdnsParseError::MalformedQuery);
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

    /// Converts the [`MdnsQuery`] to raw bytes.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.to_bytes_extend(&mut buffer);
        buffer
    }

    /// Extends the `buffer` with the raw bytes that form this [`MdnsQuery`].
    #[inline]
    pub fn to_bytes_extend(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.name.to_wire_format());
        buffer.extend_from_slice(&Into::<[u8; 2]>::into(self.query_type));
        buffer.extend_from_slice(&Into::<[u8; 2]>::into(self.query_class));
    }

    /// Returns an immutable reference to the name being queried.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &MdnsName {
        &self.name
    }

    /// Returns the query [`MdnsType`].
    #[inline]
    #[must_use]
    pub fn query_type(&self) -> MdnsType {
        self.query_type
    }

    /// Returns the query [`MdnsClass`].
    #[inline]
    #[must_use]
    pub fn query_class(&self) -> MdnsClass {
        self.query_class
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Achieve 100% test coverage.

    #[test]
    fn test_query() {
        let query = MdnsQuery::new(
            MdnsName::from_name("my_sensor._http._tcp.local.").unwrap(),
            MdnsType::A,
            MdnsClass::IN,
        );
        assert_eq!(query.name().to_string(), "my_sensor._http._tcp.local.");
        assert_eq!(query.query_type(), MdnsType::A);
        assert_eq!(query.query_class(), MdnsClass::IN);
    }

    #[test]
    fn test_query_from_bytes() {
        // TODO: Improve this test, perhaps split it into two different tests?
        // Validate that an mDNS query can be converted to bytes, then converted
        // back into an mDNS query:
        let query_a: MdnsQuery = MdnsQuery::new(
            MdnsName::from_name("test_service._http._tcp.local.").unwrap(),
            MdnsType::PTR,
            MdnsClass::IN,
        );
        let query_a_bytes: Vec<u8> = query_a.to_bytes();
        let mut offset: usize = 0;
        let query_b: MdnsQuery = MdnsQuery::from_bytes(
            &query_a_bytes,
            &mut offset,
        ).expect("Failed to convert `query_a` to `query_b`");
        assert_eq!(query_a, query_b);
        assert_eq!(offset, query_a_bytes.len());
    }
}