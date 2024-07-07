//! # ESP mDNS - Service
//! This module contains high-level service-related logic and interacts with the
//! protocol and network modules to handle mDNS operations.

use heapless::FnvIndexMap;

/// Defines errors that can occur when interacting with [`MdnsService`] or
/// [`MdnsTxtRecords`].
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum MdnsServiceError {
    /// Indicates that there are not more spaces on the underlying
    /// [`MdnsTxtRecords`] instance.
    TxtRecordsFull,
}

impl core::fmt::Display for MdnsServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TxtRecordsFull => write!(f, "TXT records are full."),
        }
    }
}

/// A heapless mDNS TXT record storage that holds a maximum of `16` records.
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
/// ```
/// version=1.0
/// path=/api
/// secure=true
/// description=ESP32 Web Service
/// ```
#[derive(PartialEq, Debug)]
pub struct TxtRecords {
    records: FnvIndexMap<String, String, 16>,
}

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
        Self {
            records: FnvIndexMap::new(),
        }
    }

    /// Returns the number of records within the [`TxtRecords`].
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if the [`TxtRecords`] contains no records; otherwise,
    /// returns `false`.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the capacity of the the [`TxtRecords`].
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.records.capacity()
    }

    /// Adds a new TXT record.
    /// 
    /// If the `key` provided corresponds to a record that already exists, its
    /// value will be overwritten and the old value is returned. If the `key` is
    /// new and there is space available for a new record, [`None`] is returned.
    /// If there is no space available for a new record,
    /// [`MdnsServiceError::TxtRecordsFull`] is returned instead.
    /// 
    /// The number of available TXT records is defined by `N`.
    #[inline]
    pub fn add(
        &mut self,
        key: &str,
        value: &str,
    ) -> Result<Option<String>, MdnsServiceError> {
        match self.records.insert(
            String::from(key),
            String::from(value),
        ) {
            Ok(old_value) => Ok(old_value),
            Err(_) => Err(MdnsServiceError::TxtRecordsFull),
        }
    }

    /// Removes a TXT record by key.
    /// 
    /// If the key is found, this function will return the old value associated
    /// with the key; otherwise, this function returns [`None`].
    #[inline]
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.records.remove(key)
    }

    /// Retrieves a TXT record by key.
    /// 
    /// If no TXT record exists for the given `key`, this function returns
    /// [`None`]; otherwise the record is returned.
    #[inline]
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&String> {
        self.records.get(key)
    }

    /// Serialises the TXT records into a format suitable for mDNS packets.
    /// 
    /// This function returns a vector of bytes representing the serialised TXT
    /// records.
    #[must_use]
    pub fn serialise(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        for (key, value) in &self.records {
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
}

/// A service that can be advertised via mDNS.
pub struct MdnsService {
    /// Name of the mDNS service.
    /// 
    /// This field stores the instance name of the mDNS service, which is a
    /// unique identifier for the specific instance of the service on the
    /// network. The instance name helps distinguish between multiple instances
    /// of the same service type.
    /// 
    /// ## Formatting
    /// The `instance_name` should be a human-readable string that uniquely
    /// identifies the service instance within the local network. It should be
    /// descriptive enough to allow users to differentiate it from other
    /// services of the same type.
    /// 
    /// ### Examples
    /// - `lightbulb_a3fb01`
    /// - `printer1`
    /// - `living_room_camera`
    /// 
    /// ## Notes
    /// - Ensure that `name` does not contain any special characters that might
    ///   be misinterpreted in mDNS packets.
    /// - It is good practice to keep the name concise, yet descriptive.
    /// - The `name` should be unique within the scope of the service type on
    ///   the local network to avoid conflicts.
    instance_name: String,
    /// The type of service, including the protocol.
    /// 
    /// This is typically formatted as: `_service._protocol`. For example:
    /// `_http._tcp`.
    service_type: String,
    /// The domain under which the service is registered.
    /// 
    /// For mDNS, this is typically `.local`, but custom domains can be used.
    /// For example: `.internal`.
    /// 
    /// This should contain the `.` character at the start, then be followed by
    /// lowercase alphabetic characters.
    service_domain: String,
    /// Port number on which the service is running.
    /// 
    /// This field specifies the port number where the service can be accessed.
    /// Clients discovering the service will use this port number ot connect to
    /// the service instance.
    /// 
    /// ## Valid Range
    /// The port number should be a valid TCP or UDP port, typically in the
    /// range of `0` to `65535`.
    /// 
    /// ## Notes
    /// - Ensure that the port number is correctly configured to match the
    ///   service being advertised.
    /// - Commonly used ports might require administrative privileges to bind on
    ///   some systems.
    port: u16,
    /// mDNS TXT records for the service.
    /// 
    /// For more information, see [`MdnsTxtRecords`].
    txt_records: TxtRecords,
}

impl MdnsService {
    pub const DEFAULT_DOMAIN: &'static str = ".local";

    /// Creates a new [`MdnsService`].
    #[inline(always)]
    #[must_use]
    pub fn new(
        instance_name: &str,
        service_type: &str,
        service_domain: &str,
        port: u16,
        txt_records: TxtRecords,
    ) -> Self {
        Self {
            instance_name: String::from(instance_name),
            service_type: String::from(service_type),
            service_domain: String::from(service_domain),
            port,
            txt_records,
        }
    }

    /// Returns the name of the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn instance_name(&self) -> &String {
        &self.instance_name
    }

    /// Returns the type of the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn service_type(&self) -> &String {
        &self.service_type
    }

    /// Returns the domain of the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn service_domain(&self) -> &String {
        &self.service_domain
    }

    /// Returns the port that the [`MdnsService`] exists at.
    #[inline]
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns an immutable reference to the underlying [`MdnsTxtRecords`] for
    /// the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn records(&self) -> &TxtRecords {
        &self.txt_records
    }

    /// Returns a mutable reference to the underlying [`MdnsTxtRecords`] for the
    /// [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn records_mut(&mut self) -> &mut TxtRecords {
        &mut self.txt_records
    }

    /// Adds a TXT record to the [`MdnsService`].
    /// 
    /// For more information, see [`MdnsTxtRecords::add`].
    // TODO: Complete documentation for this function.
    #[inline]
    pub fn add_record(
        &mut self,
        key: &str,
        value: &str,
    ) -> Result<Option<String>, MdnsServiceError> {
        self.txt_records.add(key, value)
    }

    /// Removes a TXT record from the [`MdnsService`].
    /// 
    /// For more information, see [`MdnsTxtRecords::remove`].
    // TODO: Complete documentation for this function.
    #[inline]
    pub fn remove_record(
        &mut self,
        key: &str,
    ) -> Option<String> {
        self.txt_records.remove(key)
    }

    /// Returns the TXT record for the given `key`.
    /// 
    /// For more information, see [`MdnsTxtRecords::get`].
    // TODO: Complete documentation for this function.
    #[inline]
    #[must_use]
    pub fn get_record(
        &self,
        key: &str,
    ) -> Option<&String> {
        self.txt_records.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_txt_records() {
        let records = TxtRecords::new();
        assert!(records.is_empty());
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_default_txt_records() {
        let new = TxtRecords::new();
        let default = TxtRecords::default();
        assert_eq!(new, default);
    }

    #[test]
    fn test_add_txt_records() {
        // Create new records:
        let mut records = TxtRecords::new();
        assert_eq!(records.len(), 0);

        // Create the version record:
        records.add("version", "1.0").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records.get("version"), Some(&"1.0".to_owned()));

        // Override the version record:
        records.add("version", "1.1").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records.get("version"), Some(&"1.1".to_owned()));

        // Add a new record:
        records.add("path", "/api").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records.get("version"), Some(&"1.1".to_owned()));
        assert_eq!(records.get("path"), Some(&"/api".to_owned()));

        // Add more records until the records reaches its capacity:
        for i in 2..records.capacity() {
            records.add(format!("test_record_{i}").as_str(), "test").unwrap();
        }
        // Confirm that the length matches the capacity:
        assert_eq!(records.len(), records.capacity());

        // Add one more record and expect it to fail:
        assert_eq!(
            records.add("this_should_fail", "too_many_elements").err(),
            Some(MdnsServiceError::TxtRecordsFull)
        );
    }

    #[test]
    fn test_remove_txt_records() {
        // Create records:
        let mut records = TxtRecords::new();
        records.add("record_0", "value_0").unwrap();
        records.add("record_1", "value_1").unwrap();
        records.add("record_2", "value_2").unwrap();
        records.add("record_3", "value_3").unwrap();
        assert_eq!(records.len(), 4);

        // Remove record:
        assert_eq!(records.remove("record_2"), Some("value_2".to_owned()));
        assert_eq!(records.len(), 3);
        assert_eq!(records.get("record_1"), Some(&"value_1".to_owned()));
        assert_eq!(records.get("record_3"), Some(&"value_3".to_owned()));
        assert_eq!(records.get("record_4"), Some(&"value_4".to_owned()));

        // Remove non-existent record:
        assert_eq!(records.remove("record_2"), None);
        assert_eq!(records.len(), 3);
        assert_eq!(records.remove("non_existent"), None);
        assert_eq!(records.len(), 3);

        // Remove remaining records:
        assert_eq!(records.remove("record_4"), Some("value_4".to_owned()));
        assert_eq!(records.len(), 2);
        assert_eq!(records.remove("record_1"), Some("value_1".to_owned()));
        assert_eq!(records.len(), 1);
        assert_eq!(records.remove("record_3"), Some("value_3".to_owned()));
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_serialise_txt_records() {
        // Create empty records:
        let mut records = TxtRecords::new();
        assert_eq!(records.len(), 0);
        assert_eq!(records.serialise(), Vec::new());
        
        // Populate records:
        records.add("version", "0.1.0").unwrap();
        records.add("path", "/api").unwrap();
        records.add("type", "sensor").unwrap();
        assert_eq!(records.len(), 3);

        // Validate serialised records:
        assert_eq!(
            records.serialise(),
            b"version=0.1.0\x00path=/api\x00type=sensor\x00".to_vec(),
        );
    }

    // TODO: Add unit tests for other types here
}