use alloc::vec::Vec;

use super::{
    MdnsClass,
    MdnsName,
    MdnsType,
    MdnsParseError,
};

use crate::txt_record::{
    TxtRecords,
    TxtRecordError,
};

/// Represents an mDNS response.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct MdnsResponse {
    /// The name associated with this response.
    name: MdnsName,
    /// The type of the response.
    response_type: MdnsType,
    /// The class of the response, typically IN (Internet).
    response_class: MdnsClass,
    /// The time to live for this response.
    ttl: u32,
    /// The actual data of the response.
    data: Vec<u8>,
}

impl MdnsResponse {
    /// Maximum length of [`Self::data`].
    pub const MAX_DATA_LENGTH: usize = u16::MAX as usize;

    /// Creates a new mDNS [`MdnsResponse`].
    #[inline]
    #[must_use]
    pub fn new(
        name: MdnsName,
        response_type: MdnsType,
        response_class: MdnsClass,
        ttl: u32,
        data: Vec<u8>,
    ) -> Self {
        assert!(data.len() <= Self::MAX_DATA_LENGTH);
        Self {
            name,
            response_type,
            response_class,
            ttl,
            data,
        }
    }

    /// Converts raw query bytes into a [`MdnsResponse`] instance. 
    pub fn from_bytes(
        bytes: &[u8],
        offset: &mut usize,
    ) -> Result<Self, MdnsParseError> {
        // Create a counter to track the new offset. This will become the new
        // offset when the function finishes. The reason a second counter is
        // used is to make this function act "transactionally". For example, if
        // this function encounters an error mid-execution, the `offset` does
        // not change because the function did not complete. This ensures that
        // the `offset` passed into the function only gets updated if this
        // function completes successfully:
        let mut i: usize = *offset;

        // The first part of a response packet is the name. The name uses wire
        // formatting. This should be read first:
        let name: MdnsName = match MdnsName::from_wire_format(bytes, &mut i) {
            Ok(name) => name,
            Err(error) => return Err(MdnsParseError::NameError(error)),
        };

        // After the name, 10 bytes of information is expected:
        // - `response_type` (2 bytes)
        // - `response_class` (2 bytes)
        // - `ttl` (4 bytes)
        // - `data_length` (2 bytes)
        //
        // This totals 10 bytes of data. We should first validate that there are
        // 10 bytes of data available to be read:
        if bytes.len() - i < 10 {
            return Err(MdnsParseError::MalformedResponse);
        }
        // We can now read the bytes and apply the offset:
        // TODO: This can be performed using `unchecked` functions since we have
        // confirmed that the bytes exist above:
        let response_type = u16::from_be_bytes([bytes[i], bytes[i + 1]]).into();
        let response_class = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]).into();
        let ttl = u32::from_be_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]]);
        let data_length = u16::from_be_bytes([bytes[i + 8], bytes[i + 9]]) as usize;
        i += 10;

        // Following the end of the last section, there should be `data_length`
        // bytes containing a payload:
        let data: Vec<u8> = if data_length > 0 {
            // There is a data payload; therefore, we should check that
            // `data_length` bytes exist:
            if bytes.len() - i < data_length {
                return Err(MdnsParseError::MalformedResponse);
            }
            // We can now read the bytes and apply the offset:
            let data: Vec<u8> = bytes[i..(i+data_length)].to_vec();
            i += data_length;
            data
        } else {
            Vec::new()
        };

        // The data required to construct the response has been read, we can now
        // apply the final offset value and return the response:
        *offset = i;
        Ok(Self {
            name,
            response_type,
            response_class,
            ttl,
            data,
        })
    }// Read the response data:

    /// Converts this [`MdnsResponse`] into raw bytes.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.to_bytes_extend(&mut buffer);
        buffer
    }

    /// Writes the raw byte representation of this [`MdnsResponse`] to the `buffer`.
    #[inline]
    pub fn to_bytes_extend(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.name.to_wire_format());
        buffer.extend_from_slice(&Into::<[u8; 2]>::into(self.response_type));
        buffer.extend_from_slice(&Into::<[u8; 2]>::into(self.response_class));
        buffer.extend_from_slice(&self.ttl.to_be_bytes());
        buffer.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&self.data);
    }

    /// Creates a new A record mDNS [`MdnsResponse`].
    #[must_use]
    pub fn new_a(
        name: MdnsName,
        ttl: u32,
        ipv4_bytes: Vec<u8>,
    ) -> Self {
        assert_eq!(ipv4_bytes.len(), 4);
        Self {
            name,
            response_type: MdnsType::A,
            response_class: MdnsClass::IN,
            ttl,
            data: ipv4_bytes,
        }
    }

    /// Creates a new AAAA record mDNS [`MdnsResponse`].
    #[must_use]
    pub fn new_aaaa(
        name: MdnsName,
        ttl: u32,
        ipv6_bytes: Vec<u8>,
    ) -> Self {
        assert_eq!(ipv6_bytes.len(), 16);
        Self {
            name,
            response_type: MdnsType::AAAA,
            response_class: MdnsClass::IN,
            ttl,
            data: ipv6_bytes,
        }
    }

    /// Creates a new SRV mDNS [`MdnsResponse`].
    /// 
    /// An SRV response is a type of DNS response that specifies information
    /// about available services in a domain. This type of response is used to
    /// locate servers that provide specific services. An SRV response provides
    /// details about the target host(s) that offer the requested service,
    /// including their priority, weight, port number, and the hostname of the
    /// server.
    #[must_use]
    pub fn new_srv(
        name: MdnsName,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        hostname_bytes: &[u8],
    ) -> Self {
        let mut data = Vec::new();
        data.extend(priority.to_be_bytes());
        data.extend(weight.to_be_bytes());
        data.extend(port.to_be_bytes());
        data.extend_from_slice(hostname_bytes);
        assert!(data.len() <= Self::MAX_DATA_LENGTH);
        Self {
            name,
            response_type: MdnsType::SRV,
            response_class: MdnsClass::IN,
            ttl,
            data,
        }
    }

    /// Creates a new TXT mDNS [`MdnsResponse`].
    /// 
    /// TXT mDNS responses contain additional information about the service in
    /// key-value pairs. For example: `MyDevice._http._tcp.local.` might contain
    /// information like `path=/index.html`.
    pub fn new_txt(
        name: MdnsName,
        ttl: u32,
        txt_records: &TxtRecords,
    ) -> Result<Self, TxtRecordError> {
        let data: Vec<u8> = txt_records.to_wire_format()?;
        Ok(Self {
            name,
            response_type: MdnsType::TXT,
            response_class: MdnsClass::IN,
            ttl,
            data,
        })
    }

    /// Returns the name associated with this response.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &MdnsName {
        &self.name
    }

    /// Returns the type of the response.
    #[inline]
    #[must_use]
    pub fn response_type(&self) -> &MdnsType {
        &self.response_type
    }

    /// Returns the class of the response.
    #[inline]
    #[must_use]
    pub fn response_class(&self) -> &MdnsClass {
        &self.response_class
    }

    /// Returns the time to live for this response.
    #[inline]
    #[must_use]
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns the data length of this response.
    #[inline]
    #[must_use]
    pub fn data_length(&self) -> u16 {
        self.data.len() as u16
    }

    /// Returns the actual data of the response.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Sets the time to live for this response.
    #[inline]
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    /// Sets the data for this response.
    /// 
    /// # Panics
    /// This function will panic if `data.len() > Self::MAX_DATA_LENGTH`.
    #[inline]
    pub fn set_data(&mut self, data: Vec<u8>) {
        assert!(data.len() <= Self::MAX_DATA_LENGTH);
        self.data = data;
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    // TODO: Achieve 100% test coverage.

    #[test]
    fn test_response() {
        let mut response = MdnsResponse::new(
            MdnsName::from_name("my_sensor._http._tcp.local.").unwrap(),
            MdnsType::A,
            MdnsClass::IN,
            120,
            [127, 0, 0, 1].to_vec(),
        );

        assert_eq!(response.name().to_string(), "my_sensor._http._tcp.local.");
        assert_eq!(response.response_type(), &MdnsType::A);
        assert_eq!(response.response_class(), &MdnsClass::IN);
        assert_eq!(response.ttl(), 120);
        assert_eq!(response.data_length(), 4);
        assert_eq!(response.data(), &[127, 0, 0, 1]);

        response.set_ttl(240);
        assert_eq!(response.ttl(), 240);

        response.set_data([192, 168, 0, 1].to_vec());
        assert_eq!(response.data_length(), 4);
        assert_eq!(response.data(), &[192, 168, 0, 1]);
    }

    #[test]
    fn test_response_from_bytes() {
        // TODO: Improve this test, perhaps split it into two tests?
        // Validate that an mDNS response can be converted to bytes, then
        // converted back into an mDNS response:
        let response_a: MdnsResponse = MdnsResponse::new(
            MdnsName::from_name("test_service._http._tcp.local.").unwrap(),
            MdnsType::PTR,
            MdnsClass::IN,
            120,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].to_vec(),
        );
        let response_a_bytes: Vec<u8> = response_a.to_bytes();
        let mut offset: usize = 0;
        let response_b: MdnsResponse = MdnsResponse::from_bytes(
            &response_a_bytes,
            &mut offset,
        ).expect("Failed to convert `response_a` to `response_b`");
        assert_eq!(response_a, response_b);
        assert_eq!(offset, response_a_bytes.len());
    }
}