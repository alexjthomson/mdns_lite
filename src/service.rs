//! # ESP mDNS - Service
//! This module contains high-level service-related logic and interacts with the
//! protocol and network modules to handle mDNS operations.

use heapless::FnvIndexMap;
use thiserror::Error;

use crate::{
    MdnsClass,
    MdnsName,
    MdnsType,
    MdnsPacket,
    MdnsResponse,
};

/// Defines errors that can occur when interacting with [`MdnsService`] or
/// [`MdnsTxtRecords`].
#[derive(PartialEq, Eq, Clone, Debug, Error)]
pub enum MdnsServiceError {
    /// Indicates that there are not more spaces on the underlying
    /// [`MdnsTxtRecords`] instance.
    #[error("TXT records are full.")]
    TxtRecordsFull,
    #[error("Missing instance name labels.
    There must be at least one instance name label provided.")]
    MissingInstanceNameLabels,
    #[error("Invalid instance name: `{0}`.")]
    InvalidInstanceName(String),
    #[error("Missing service type labels.
    There must be at least one service type label provided.")]
    MissingServiceTypeLabels,
    #[error("Invalid service type name label: `{0}`.
    Service type names must start with a `_` character, followed by only alpha-numeric characters and hyphens.")]
    InvalidServiceTypeName(String),
    #[error("Invalid service type protocol: `{0}`.
    Only `_tcp` and `_udp` are supported service type protocols.")]
    InvalidServiceTypeProtocol(String),
    #[error("Invalid service domain: `{0}`.")]
    InvalidServiceDomain(String),
    #[error("TXT record entry too long.
    TXT records can be a maximum of 254 bytes long (key + value).")]
    TxtRecordEntryTooLong,
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

    /// Converts the [`TxtRecords`] into wire format.
    /// 
    /// This format contains the length of each record at the start, followed by
    /// the record itself.
    pub fn to_wire_format(&self) -> Result<Vec<u8>, MdnsServiceError> {
        let mut bytes = Vec::new();
        for (key, value) in &self.records {
            let kv_string = format!("{key}={value}");
            let kv_length = kv_string.len();
            if kv_length > 255 {
                return Err(MdnsServiceError::TxtRecordEntryTooLong);
            }
            bytes.push(kv_length as u8);
            bytes.extend_from_slice(kv_string.as_bytes());
        }
        Ok(bytes)
    }

    // TODO: Add `from_wire_format`.
}

/// A service that can be advertised via mDNS.
pub struct MdnsService {
    /// Labels that belong to the instance name.
    /// 
    /// This field collectively describes the instance name of the mDNS service,
    /// which should be a unique identifier for the specific instance of the
    /// service on the network. The instance name helps distinguish between
    /// multiple instances of the same service type.
    /// 
    /// Each label in the instance name should uniquely identify the service
    /// instance within the local network. It should be descriptive enough to
    /// allow users to differentiate it from other services of the same type.
    /// 
    /// ## Examples
    /// - `lightbulb_a3fb01`
    /// - `printer_1`
    /// - `security_camera`
    /// 
    /// ## Notes
    /// - It is good practice to keep the name concise, yet descriptive.
    /// - The name should be unique within the scope of the service type on the
    ///   local network to avoid conflicts.
    /// - Typically the instance name only consists of one label; however, it is
    ///   within the specifications of mDNS to support multiple. More than one
    ///   label is not typically seen in practice.
    instance_name_labels: Vec<String>,
    /// Labels that describe the service type.
    /// 
    /// The service type describes the type of service being offered and the
    /// protocol over which the service is available. This helps clients
    /// discover the services available on the network and understand how to
    /// interact with them.
    /// 
    /// A typical service type contains two main components:
    /// 1. **Service Name**: Specifies the type of service (e.g. `_http`,
    ///    `_printer`).
    /// 2. **Protocol**: Specifies the protocol used by the service, which can
    ///    be either `_tcp` or `_udp`.
    /// 
    /// At the very minimum, the service type should contain the protocol used.
    /// Additionally, the protocol should always be the last label specified.
    /// 
    /// More than two labels is supported by the mDNS specifications, but this
    /// is rarely seen in practice. Typically either two or one label is
    /// included.
    /// 
    /// All labels specified within the service type labels should start with an
    /// underscore, and should then only contain ascii alphanumeric characters
    /// and hyphens.
    service_type_labels: Vec<String>,
    /// The domain under which the service is registered.
    /// 
    /// For mDNS, this is typically `local`, but custom domains are supported by
    /// the mDNS specifications. For example, you could use `internal` instead
    /// of `local`.
    /// 
    /// This should not include the leading `.` character, and should only
    /// contain lowercase alphabetic characters.
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
    /// Default value of [`Self::service_domain`].
    pub const DEFAULT_DOMAIN: &'static str = "local";

    /// Returns [`Err`] if the `instance_name` is invalid; otherwise, returns
    /// [`Ok`].
    pub fn validate_instance_name(
        instance_name: &str
    ) -> Result<Vec<String>, MdnsServiceError> {
        let labels: Vec<String> = instance_name
            .split('.')
            .map(|s| s.to_owned())
            .collect();
        if labels.is_empty() {
            return Err(MdnsServiceError::MissingInstanceNameLabels)
        }

        // Validate each label:
        for label in labels.iter() {
            if label.chars().any(|c| c == '.' || c == '%' || c.is_control()) {
                return Err(MdnsServiceError::InvalidInstanceName(label.clone()));
            }
        }

        Ok(labels)
    }

    /// Returns [`Err`] if the `service_type` is invalid; otherwise, returns
    /// [`Ok`].
    pub fn validate_service_type(
        service_type: &str,
    ) -> Result<Vec<String>, MdnsServiceError> {
        let labels: Vec<String> = service_type
            .split('.')
            .map(|s| s.to_owned())
            .collect();
        if labels.is_empty() {
            return Err(MdnsServiceError::MissingServiceTypeLabels);
        }

        // Validate non-protocol labels:
        let non_protocol_labels = labels.len() - 1;
        if non_protocol_labels > 0 {
            for i in 0..non_protocol_labels {
                let label = unsafe {
                    // SAFETY: We know this is in range since
                    // `non_protocol_labels` is guaranteed to be in range:
                    labels.get_unchecked(i)
                };
                if !label.starts_with('_') || label.chars().skip(1).any(|c| !c.is_ascii_alphanumeric() && c != '-') {
                    return Err(MdnsServiceError::InvalidServiceTypeName(label.clone()));
                }
            }
        }

        // Validate protocol label:
        let service_protocol = unsafe {
            // SAFETY: `non_protocol_labels` points towards the last element in
            // the labels vector, therefore it must be in range:
            labels.get_unchecked(non_protocol_labels)
        };
        if service_protocol != "_tcp" && service_protocol != "_udp" {
            return Err(MdnsServiceError::InvalidServiceTypeProtocol(service_protocol.clone()));
        }

        Ok(labels)
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
        let instance_name_labels = Self::validate_instance_name(instance_name)?;
        let service_type_labels = Self::validate_service_type(service_type)?;
        let service_domain = Self::validate_service_domain(service_domain)?;
        Ok(Self { instance_name_labels, service_type_labels, service_domain, port, txt_records })
    }

    /// Returns the labels in order for the [`MdnsService`].
    /// 
    /// ## Notes
    /// This builds the returned [`Vec<String>`] every time the function is
    /// called. Avoid calling this frequently or cache the result.
    #[inline]
    #[must_use]
    pub fn labels(&self) -> Vec<String> {
        let capacity: usize = self.instance_name_labels.len() + self.service_type_labels.len() + 1;
        let mut labels: Vec<String> = Vec::with_capacity(capacity);
        labels.extend(self.instance_name_labels.iter().cloned());
        labels.extend(self.service_type_labels.iter().cloned());
        labels.push(self.service_domain.clone());
        labels
    }

    /// Returns the name of the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn instance_name_labels(&self) -> &Vec<String> {
        &self.instance_name_labels
    }

    /// Returns the type of the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn service_type_labels(&self) -> &Vec<String> {
        &self.service_type_labels
    }

    /// Returns an immutable reference to the service type protocol.
    /// 
    /// This is equal to either `_tcp` or `_udp`.
    #[inline]
    #[must_use]
    pub fn service_type_protocol(&self) -> &String {
        self.service_type_labels.last().unwrap()
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

    /// Calculates and returns the full service [`DnsName`].
    #[must_use]
    pub fn service_name(&self) -> MdnsName {
        MdnsName::new(self.labels().to_vec())
    }

    /// Calculates and returns the full host [`DnsName`].
    /// 
    /// This is the same as the [`Self::service_name()`], but without the
    /// service type included.
    #[must_use]
    pub fn host_name(&self) -> MdnsName {
        let capacity: usize = self.instance_name_labels.len() + 1;
        let mut labels: Vec<String> = Vec::with_capacity(capacity);
        labels.extend(self.instance_name_labels.iter().cloned());
        labels.push(self.service_domain.clone());
        MdnsName::new(labels.to_vec())
    }

    /// Creates an [`MdnsPacket`] that announces this service.
    pub fn to_service_announcement_packet(
        &self,
        ttl: u32,
        ipv4: Option<&Vec<u8>>,
        ipv6: Option<&Vec<u8>>,
    ) -> Result<MdnsPacket, MdnsServiceError> {
        let service_name = self.service_name();
        let service_name_bytes = service_name.to_wire_format();
        let host_name = self.host_name();
        let host_name_bytes = host_name.to_wire_format();

        // Construct answers:
        let mut answers = Vec::with_capacity(3);

        // PTR Record:
        // This record maps the service type to the specific service instance.
        answers.push(MdnsResponse::new(
            MdnsName::new({
                // The DNS name for the PTR record should only contain the
                // service type:
                let mut service_type_labels = Vec::new();
                service_type_labels.extend(self.service_type_labels.iter().cloned());
                service_type_labels.push(self.service_domain.clone());
                service_type_labels
            }),
            MdnsType::PTR,
            MdnsClass::IN,
            ttl,
            service_name_bytes.clone(),
        ));

        // SRV Record:
        // This record provides the hostname and port where the service can be
        // accessed.
        answers.push(MdnsResponse::new_srv(
            service_name.clone(),
            ttl,
            0,
            0,
            self.port,
            &host_name_bytes,
        ));

        // TXT Record:
        // This record contains the key-value pairs with additional information
        // about the service. This record is only included if there are any TXT
        // records included with the service:
        if !self.txt_records.is_empty() {
            answers.push(MdnsResponse::new(
                service_name.clone(),
                MdnsType::TXT,
                MdnsClass::IN,
                ttl,
                self.txt_records.to_wire_format()?,
            ));
        }

        // Construct authority records:
        // The authority records maps the host name to the device IPv4 and IPv6
        // addresses.
        let mut authoritative_nameservers = Vec::new();
        if let Some(ipv4) = ipv4 {
            authoritative_nameservers.push(MdnsResponse::new_a(
                host_name.clone(),
                ttl,
                ipv4.clone(),
            ));
        }
        if let Some(ipv6) = ipv6 {
            authoritative_nameservers.push(MdnsResponse::new_aaaa(
                host_name,
                ttl,
                ipv6.clone(),
            ));
        }

        // Construct and return the packet:
        Ok(MdnsPacket::new_with_records(
            0,
            Vec::new(),
            answers,
            authoritative_nameservers,
            Vec::new(),
        ))
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
        assert_eq!(service.instance_name_labels().first().unwrap(), "bedroom_lightbulb");
        assert_eq!(service.service_type_labels(), &vec!["_http", "_tcp"]);
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
        assert_eq!(
            MdnsService::validate_instance_name("ValidName"),
            Ok(vec!["ValidName".to_owned()])
        );
        assert_eq!(
            MdnsService::validate_instance_name("Another_Valid-Name"),
            Ok(vec!["Another_Valid-Name".to_owned()])
        );
        assert_eq!(
            MdnsService::validate_instance_name("One.Two.Three"),
            Ok(vec!["One".to_owned(), "Two".to_owned(), "Three".to_owned()])
        );
        
        // Invalid instance names
        assert!(MdnsService::validate_instance_name("Invalid%Name").is_err());
        assert!(MdnsService::validate_instance_name("Invalid\u{0000}Name").is_err());
    }

    #[test]
    fn test_validate_service_type() {
        // Valid service types
        assert_eq!(
            MdnsService::validate_service_type("_udp"),
            Ok(vec!["_udp".to_owned()])
        );
        assert_eq!(
            MdnsService::validate_service_type("_http._tcp"),
            Ok(vec!["_http".to_owned(), "_tcp".to_owned()])
        );
        assert_eq!(
            MdnsService::validate_service_type("_ftp._udp"),
            Ok(vec!["_ftp".to_owned(), "_udp".to_owned()])
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