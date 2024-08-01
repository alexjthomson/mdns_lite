use alloc::{
    collections::btree_map::BTreeMap,
    string::String,
    vec::Vec,
};

/// Describes various errors that could happen while interacting with mDNS
/// [`TxtRecords`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum TxtRecordError {
    EntryTooLong,
}

impl core::fmt::Display for TxtRecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EntryTooLong => write!(f, "TXT record entry is longer than the maximum length of 254 bytes (key + value)."),
        }
    }
}

/// A heapless mDNS TXT record storage.
/// 
/// TXT records are used to store additional information about a service in the
/// form of key-value pairs. These records provide metadata about the service
/// being advertised and can be used to convey various details that might be
/// useful to clients discovering the service.
/// 
/// ## Example Records
/// TXT records are often used to provide information such as:
/// - _Version_: The version number of the service.
/// - _Path_: A specific path or endpoint that the client should connect to.
/// - _Protocol Information_: Details about the protocols supported or required.
/// - _Configuration Details_: Any configuration parameters that the client
///   might need.
/// - _Service Description_: A human-readable description of the service.
/// 
/// ## Record Format
/// TXT records are typically formatted as strings, where each key-value pair is
/// represented as `key=value`. Multiple TXT records can be included, each
/// providing a different piece of information about the service.
/// 
/// ### Example
/// ```ignore
/// version=1.0
/// path=/api
/// secure=true
/// description=ESP32 Web Service
/// ```
#[derive(PartialEq, Debug)]
pub struct TxtRecords(BTreeMap<String, String>);

impl Default for TxtRecords {
    #[inline]
    #[must_use]
    fn default() -> Self {
        Self::new()
    }
}

impl TxtRecords {
    /// Creates a new, empty set of mDNS TXT records.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Returns the number of records within the [`TxtRecords`].
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the [`TxtRecords`] contains no records; otherwise,
    /// returns `false`.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Adds a new TXT record.
    /// 
    /// If the `key` provided corresponds to a record that already exists, its
    /// value will be overwritten and the old value is returned. Otherwise, if
    /// the `key` is unique, [`None`] is returned.
    #[inline]
    pub fn add(
        &mut self,
        key: &str,
        value: &str,
    ) -> Option<String> {
        self.0.insert(String::from(key), String::from(value))
    }

    /// Removes a TXT record by key.
    /// 
    /// If the key is found, this function will return the old value associated
    /// with the key; otherwise, this function returns [`None`].
    #[inline]
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.0.remove(key)
    }

    /// Retrieves a TXT record by key.
    /// 
    /// If no TXT record exists for the given `key`, this function returns
    /// [`None`]; otherwise the record is returned.
    #[inline]
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    /// Serialises the TXT records into a format suitable for mDNS packets.
    /// 
    /// This function returns a vector of bytes representing the serialised TXT
    /// records.
    #[must_use]
    pub fn serialise(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        for (key, value) in &self.0 {
            // Create the TXT record:
            let mut record = key.clone();
            record.push('=');
            record.push_str(value);
            // Push to the buffer:
            buffer.extend_from_slice(record.as_bytes());
            buffer.push(0_u8); // Null terminator for each record
        }
        buffer
    }

    /// Converts the [`TxtRecords`] into wire format.
    /// 
    /// This format contains the length of each record at the start, followed by
    /// the record itself.
    pub fn to_wire_format(&self) -> Result<Vec<u8>, TxtRecordError> {
        let mut bytes = Vec::new();
        for (key, value) in &self.0 {
            let kv_string = alloc::format!("{key}={value}");
            let kv_length = kv_string.len();
            if kv_length > 255 {
                return Err(TxtRecordError::EntryTooLong);
            }
            bytes.push(kv_length as u8);
            bytes.extend_from_slice(kv_string.as_bytes());
        }
        Ok(bytes)
    }

    // TODO: Add `from_wire_format`.
}