//! # ESP mDNS - Service
//! This module contains high-level service-related logic and interacts with the
//! protocol and network modules to handle mDNS operations.

use heapless::FnvIndexMap;
use thiserror::Error;

/// Defines errors that can occur when interacting with [`MdnsService`] or
/// [`MdnsTxtRecords`].
#[derive(PartialEq, Eq, Clone, Debug, Error)]
pub enum MdnsServiceError {
    /// Indicates that there are not more spaces on the underlying
    /// [`MdnsTxtRecords`] instance.
    #[error("TXT records are full.")]
    TxtRecordsFull,
    #[error("Invalid instance name: `{0}`.")]
    InvalidInstanceName(String),
    #[error("Invalid service type label count (found: `{0}`, expected `2`).")]
    InvalidServiceTypeCount(usize),
    #[error("Invalid service type name label: `{0}`.
    Service type names must start with a `_` character, followed by only alpha-numeric characters and hyphens.")]
    InvalidServiceTypeName(String),
    #[error("Invalid service type protocol: `{0}`.
    Only `_tcp` and `_udp` are supported service type protocols.")]
    InvalidServiceTypeProtocol(String),
    #[error("Invalid service domain: `{0}`.")]
    InvalidServiceDomain(String),
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
/// ```ignore
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
    /// Contains each of the labels for the [`MdnsService`].
    /// 
    /// An mDNS service can have at most 4 labels:
    /// 
    /// # 1. Instance Name
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
    /// ## Examples
    /// - `lightbulb_a3fb01`
    /// - `printer1`
    /// - `living_room_camera`
    /// 
    /// ## Notes
    /// - It is good practice to keep the name concise, yet descriptive.
    /// - The name should be unique within the scope of the service type on the
    ///   local network to avoid conflicts.
    /// 
    /// # 2. Service Type Name
    /// This is part of the service type. This label should start with an
    /// underscore and should only contain ascii alphanumeric characters and
    /// hyphens.
    /// 
    /// ## Examples
    /// - `_http`
    /// - `_printer`
    /// 
    /// # 3. Service Type Protocol
    /// This is part of the service type. This label should contain the protocol
    /// used by the service. There are only two values that this can be:
    /// - `_tcp`
    /// - `_udp`
    /// 
    /// # 4. Service Domain
    /// The domain under which the service is registered.
    /// 
    /// For mDNS, this is typically `local`, but custom domains can be used.
    /// For example: `internal`.
    /// 
    /// This should not include the `.` character and should only contain
    /// lowercase alphabetic characters.
    labels: heapless::Vec<String, 4>,
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
    /// Default value of [`Self::service_domain`].
    pub const DEFAULT_DOMAIN: &'static str = "local";

    /// Returns [`Err`] if the `instance_name` is invalid; otherwise, returns
    /// [`Ok`].
    pub fn validate_instance_name(
        instance_name: &str
    ) -> Result<String, MdnsServiceError> {
        if instance_name.chars().any(|c| c == '.' || c == '%' || c.is_control()) {
            Err(MdnsServiceError::InvalidInstanceName(instance_name.to_owned()))
        } else {
            Ok(String::from(instance_name))
        }
    }

    /// Returns [`Err`] if the `service_type` is invalid; otherwise, returns
    /// [`Ok`].
    pub fn validate_service_type(
        service_type: &str,
    ) -> Result<(String, String), MdnsServiceError> {
        // Split the labels into a vector of Strings:
        let labels: Vec<String> = service_type
            .split('.')
            .map(|s| s.to_owned())
            .collect();

        // Validate that there are exactly two labels. These two labels are the
        // `service_name` and the `protocol`:
        if labels.len() != 2 {
            return Err(MdnsServiceError::InvalidServiceTypeCount(labels.len()));
        }

        // Validate the service name:
        let service_name = unsafe {
            // SAFETY: We checked the length of `labels` above, we know there
            // are exactly two elements:
            labels.get_unchecked(0)
        };
        if !service_name.starts_with('_')
            || service_name.chars().skip(1).any(|c| !c.is_ascii_alphanumeric() && c != '-')
        {
            return Err(MdnsServiceError::InvalidServiceTypeName(service_name.clone()));
        }

        let service_protocol = unsafe {
            // SAFETY: We checked the length of `labels` above, we know there
            // are exactly two elements:
            labels.get_unchecked(1)
        };
        if service_protocol != "_tcp" && service_protocol != "_udp" {
            return Err(MdnsServiceError::InvalidServiceTypeProtocol(service_protocol.clone()));
        }

        Ok((service_name.clone(), service_protocol.clone()))
    }

    /// Returns [`Err`] if the `service_domain` is invalid; otherwise, returns
    /// [`Ok`].
    pub fn validate_service_domain(
        service_domain: &str
    ) -> Result<String, MdnsServiceError> {
        if service_domain.chars().any(|c| c == '.' || c == '%' || c.is_control()) {
            Err(MdnsServiceError::InvalidServiceDomain(service_domain.to_owned()))
        } else {
            Ok(String::from(service_domain))
        }
    }

    /// Creates a new [`MdnsService`].
    pub fn new(
        instance_name: &str,
        service_type: &str,
        service_domain: &str,
        port: u16,
        txt_records: TxtRecords,
    ) -> Result<Self, MdnsServiceError> {
        // Validate the fields:
        let instance_name = Self::validate_instance_name(instance_name)?;
        let service_type = Self::validate_service_type(service_type)?;
        let service_domain = Self::validate_service_domain(service_domain)?;

        // Construct the labels:
        let mut labels = heapless::Vec::<String, 4>::new();
        unsafe {
            // SAFETY: We are pushing exactly four elements to the vec, we know
            // that the vec has a length of exactly four:
            labels.push_unchecked(instance_name);
            labels.push_unchecked(service_type.0);
            labels.push_unchecked(service_type.1);
            labels.push_unchecked(service_domain);
        }

        // Construct the service:
        Ok(Self { labels, port, txt_records })
    }

    /// Returns the labels in order for the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn labels(&self) -> &heapless::Vec<String, 4> {
        &self.labels
    }

    /// Returns the name of the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn instance_name(&self) -> &String {
        debug_assert_eq!(self.labels.len(), 4);
        unsafe {
            // SAFETY: `labels` has exactly four elements:
            self.labels.get_unchecked(0)
        }
    }

    /// Returns the type of the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn service_type(&self) -> String {
        debug_assert_eq!(self.labels.len(), 4);
        unsafe {
            // SAFETY: `labels` has exactly four elements:
            format!(
                "{0}.{1}",
                self.labels.get_unchecked(1),
                self.labels.get_unchecked(2),
            )
        }
    }

    /// Returns an immutable reference to the service type name.
    /// 
    /// This is typically something like `_http` or `_printer`.
    #[inline]
    #[must_use]
    pub fn service_type_name(&self) -> &String {
        debug_assert_eq!(self.labels.len(), 4);
        unsafe {
            // SAFETY: `labels` has exactly four elements:
            self.labels.get_unchecked(1)
        }
    }

    /// Returns an immutable reference to the service type protocol.
    /// 
    /// This is equal to either `_tcp` or `_udp`.
    #[inline]
    #[must_use]
    pub fn service_type_protocol(&self) -> &String {
        debug_assert_eq!(self.labels.len(), 4);
        unsafe {
            // SAFETY: `labels` has exactly four elements:
            self.labels.get_unchecked(2)
        }
    }

    /// Returns the domain of the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn service_domain(&self) -> &String {
        debug_assert_eq!(self.labels.len(), 4);
        unsafe {
            // SAFETY: `labels` has exactly four elements:
            self.labels.get_unchecked(3)
        }
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

    /// Returns the total number of TXT records in this [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn total_records(&self) -> usize {
        self.txt_records.len()
    }

    /// Adds a TXT record to the [`MdnsService`].
    /// 
    /// For more information, see [`MdnsTxtRecords::add`].
    /// 
    /// ## Returns
    /// This function returns [`Ok`] with the previous value associated with the
    /// key (if it existed), or [`Err`] if there was an error adding the record.
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
    /// 
    /// ## Returns
    /// This function returns the value of the record (if it existed).
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
    /// 
    /// ## Returns
    /// This function returns a reference to the record (if it exists.)
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
        records.add("record_1", "value_1").unwrap();
        records.add("record_2", "value_2").unwrap();
        records.add("record_3", "value_3").unwrap();
        records.add("record_4", "value_4").unwrap();
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

    /// Creates a test [`MdnsService`].
    fn create_test_mdns_service() -> MdnsService {
        MdnsService::new(
            "bedroom_lightbulb",
            "_http._tcp",
            "local",
            80,
            TxtRecords::new(),
        ).unwrap()
    }

    #[test]
    fn test_new_mdns_service() {
        let mut service = create_test_mdns_service();
        assert_eq!(service.instance_name(), "bedroom_lightbulb");
        assert_eq!(service.service_type(), "_http._tcp");
        assert_eq!(service.service_type_name(), &"_http".to_owned());
        assert_eq!(service.service_type_protocol(), &"_tcp".to_owned());
        assert_eq!(service.service_domain(), "local");
        assert_eq!(service.port(), 80);
        assert_eq!(service.total_records(), 0);
        assert_eq!(service.records().len(), 0);
        assert_eq!(service.records_mut().len(), 0);
    }

    #[test]
    fn test_add_record() {
        let mut service = create_test_mdns_service();
        assert_eq!(service.total_records(), 0);
        assert_eq!(service.add_record("version", "1.0"), Ok(None));
        assert_eq!(service.total_records(), 1);
        assert_eq!(service.add_record("version", "1.1"), Ok(Some("1.0".to_owned())));
        assert_eq!(service.total_records(), 1);
        assert_eq!(service.add_record("entry_2", "2"), Ok(None));
        assert_eq!(service.total_records(), 2);
        assert_eq!(service.add_record("entry_3", "3"), Ok(None));
        assert_eq!(service.total_records(), 3);
        assert_eq!(service.add_record("entry_4", "4"), Ok(None));
        assert_eq!(service.total_records(), 4);
        assert_eq!(service.add_record("entry_5", "5"), Ok(None));
        assert_eq!(service.total_records(), 5);
    }

    #[test]
    fn test_remove_record() {
        // Create service:
        let mut service = create_test_mdns_service();
        service.add_record("record_1", "1").unwrap();
        service.add_record("record_2", "2").unwrap();
        service.add_record("record_3", "3").unwrap();
        service.add_record("record_4", "4").unwrap();
        assert_eq!(service.total_records(), 4);

        // Start removing records:
        assert_eq!(service.remove_record("does_not_exist"), None);
        assert_eq!(service.total_records(), 4);

        assert_eq!(service.remove_record("record_1"), Some("1".to_owned()));
        assert_eq!(service.total_records(), 3);
        assert_eq!(service.remove_record("record_4"), Some("4".to_owned()));
        assert_eq!(service.total_records(), 2);
        assert_eq!(service.remove_record("record_3"), Some("3".to_owned()));
        assert_eq!(service.total_records(), 1);
        assert_eq!(service.remove_record("record_3"), None);
        assert_eq!(service.total_records(), 1);
        assert_eq!(service.remove_record("record_2"), Some("2".to_owned()));
        assert_eq!(service.total_records(), 0);
    }

    #[test]
    fn test_get_record() {
        // Create services:
        let mut service = create_test_mdns_service();
        service.add_record("record_1", "1").unwrap();
        service.add_record("record_2", "2").unwrap();
        service.add_record("record_3", "3").unwrap();
        service.add_record("record_4", "4").unwrap();
        assert_eq!(service.total_records(), 4);

        // Get services:
        assert_eq!(service.get_record("record_1"), Some(&"1".to_owned()));
        assert_eq!(service.get_record("record_0"), None);
        assert_eq!(service.get_record("record_2"), Some(&"2".to_owned()));
        assert_eq!(service.get_record("record_3"), Some(&"3".to_owned()));
        assert_eq!(service.get_record("record_4"), Some(&"4".to_owned()));
    }

    #[test]
    fn test_validate_instance_name() {
        // Valid instance names
        assert_eq!(MdnsService::validate_instance_name("ValidName"), Ok("ValidName".to_string()));
        assert_eq!(MdnsService::validate_instance_name("Another_Valid-Name"), Ok("Another_Valid-Name".to_string()));
        
        // Invalid instance names
        assert!(MdnsService::validate_instance_name("Invalid.Name").is_err());
        assert!(MdnsService::validate_instance_name("Invalid%Name").is_err());
        assert!(MdnsService::validate_instance_name("Invalid\u{0000}Name").is_err());
    }

    #[test]
    fn test_validate_service_type() {
        // Valid service types
        assert_eq!(
            MdnsService::validate_service_type("_http._tcp"),
            Ok(("_http".to_owned(), "_tcp".to_owned()))
        );
        assert_eq!(
            MdnsService::validate_service_type("_ftp._udp"),
            Ok(("_ftp".to_owned(), "_udp".to_owned()))
        );

        // Invalid service types
        assert!(MdnsService::validate_service_type("_invalid").is_err());
        assert!(MdnsService::validate_service_type("_http._invalidprotocol").is_err());
        assert!(MdnsService::validate_service_type("http._tcp").is_err());
        assert!(MdnsService::validate_service_type("_http._tcp._extra").is_err());
    }

    #[test]
    fn test_validate_service_domain() {
        // Valid service domains
        assert_eq!(MdnsService::validate_service_domain("validdomain"), Ok("validdomain".to_string()));
        assert_eq!(MdnsService::validate_service_domain("another-valid_domain"), Ok("another-valid_domain".to_string()));

        // Invalid service domains
        assert!(MdnsService::validate_service_domain("invalid.domain").is_err());
        assert!(MdnsService::validate_service_domain("invalid%domain").is_err());
        assert!(MdnsService::validate_service_domain("invalid\u{0000}domain").is_err());
    }
}