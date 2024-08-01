use alloc::{borrow::ToOwned, string::String, vec::Vec};

use crate::{MdnsClass, MdnsName, MdnsNameError, MdnsPacket, MdnsResponse, MdnsType};

use super::{txt_record::TxtRecordError, TxtRecords};

/// Describes various errors that could happen while interacting with an
/// [`MdnsService`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum MdnsServiceError {
    MissingInstanceName,
    InvalidInstanceName(String),
    MissingServiceType,
    InvalidServiceType(String),
    InvalidServiceProtocol(String),
    InvalidServiceDomain(String),
    TxtRecordError(TxtRecordError),
    NameError(MdnsNameError),
}

impl core::fmt::Display for MdnsServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingInstanceName => write!(f, "There must be at least one instance name label."),
            Self::InvalidInstanceName(instance_name) => write!(f, "Invalid instance name: `{instance_name}`."),
            Self::MissingServiceType => write!(f, "There must be at least one service type label."),
            Self::InvalidServiceType(service_type) => write!(f, "Invalid service type: `{service_type}`."),
            Self::InvalidServiceProtocol(service_protocol) => write!(f, "Invalid service protocol: `{service_protocol}`."),
            Self::InvalidServiceDomain(service_domain) => write!(f, "Invalid service domain: `{service_domain}`."),
            Self::TxtRecordError(error) => write!(f, "TXT record error: {error}"),
            Self::NameError(error) => write!(f, "Name error: {error}"),
        }
    }
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
            return Err(MdnsServiceError::MissingInstanceName)
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
            return Err(MdnsServiceError::MissingServiceType);
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
                    return Err(MdnsServiceError::InvalidServiceType(label.clone()));
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
            return Err(MdnsServiceError::InvalidServiceProtocol(service_protocol.clone()));
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
    #[inline]
    pub fn add_record(
        &mut self,
        key: &str,
        value: &str,
    ) -> Option<String> {
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
    pub fn service_name(&self) -> Result<MdnsName, MdnsNameError> {
        MdnsName::new(&self.labels())
    }

    /// Calculates and returns the full host [`DnsName`].
    /// 
    /// This is the same as the [`Self::service_name()`], but without the
    /// service type included.
    #[must_use]
    pub fn host_name(&self) -> Result<MdnsName, MdnsNameError> {
        let capacity: usize = self.instance_name_labels.len() + 1;
        let mut labels: Vec<String> = Vec::with_capacity(capacity);
        labels.extend(self.instance_name_labels.iter().cloned());
        labels.push(self.service_domain.clone());
        MdnsName::new(&labels)
    }

    /// Creates a new PTR record for this [`MdnsService`].
    fn ptr_record(&self, payload: &MdnsName, ttl: u32) -> Result<MdnsResponse, MdnsServiceError> {
        let mut labels: Vec<String> = Vec::new();
        labels.extend(self.service_type_labels.iter().cloned());
        labels.push(self.service_domain.clone());
        match MdnsName::new(&labels) {
            Ok(name) => {
                Ok(MdnsResponse::new(
                    name,
                    MdnsType::PTR,
                    MdnsClass::IN,
                    ttl,
                    payload.to_wire_format().to_vec(),
                ))
            }
            Err(error) => Err(MdnsServiceError::NameError(error))
        }
    }

    /// Creates a new SRV record for this [`MdnsService`].
    fn srv_record(&self, service_name: MdnsName, payload: &MdnsName, ttl: u32) -> MdnsResponse {
        MdnsResponse::new_srv(
            service_name,
            ttl,
            0,
            0,
            self.port,
            payload.to_wire_format(),
        )
    }

    /// Creates a new TXT record for this [`MdnsService`].
    fn txt_record(&self, service_name: MdnsName, ttl: u32) -> Option<Result<MdnsResponse, MdnsServiceError>> {
        if self.txt_records.is_empty() {
            None
        } else {
            Some(match self.txt_records.to_wire_format() {
                Ok(payload) => Ok(MdnsResponse::new(
                    service_name,
                    MdnsType::TXT,
                    MdnsClass::IN,
                    ttl,
                    payload,
                )),
                Err(error) => Err(MdnsServiceError::TxtRecordError(error))
            })
        }
    }

    /// Creates an [`MdnsPacket`] that announces this service.
    pub fn to_service_announcement_packet(
        &self,
        ttl: u32,
        ipv4: Option<&Vec<u8>>,
        ipv6: Option<&Vec<u8>>,
    ) -> Result<MdnsPacket, MdnsServiceError> {
        // Get the service name bytes:
        let service_name = match self.service_name() {
            Ok(service_name) => service_name,
            Err(error) => return Err(MdnsServiceError::NameError(error)),
        };

        // Get the host name bytes:
        let host_name = match self.host_name() {
            Ok(host_name) => host_name,
            Err(error) => return Err(MdnsServiceError::NameError(error)),
        };

        // Construct answers:
        let mut answers: Vec<MdnsResponse> = Vec::with_capacity(3);

        // PTR Record:
        // This record maps the service type to the specific service instance.
        answers.push(self.ptr_record(&service_name, ttl)?);

        // SRV Record:
        // This record provides the hostname and port where the service can be
        // accessed.
        answers.push(self.srv_record(service_name.clone(), &host_name, ttl));

        // TXT Record:
        // This record contains the key-value pairs with additional information
        // about the service. This record is only included if there are any TXT
        // records included with the service:
        if let Some(txt_record) = self.txt_record(service_name.clone(), ttl) {
            answers.push(txt_record?);
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
        assert_eq!(service.service_type_labels(), &["_http", "_tcp"]);
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
        assert_eq!(service.add_record("version", "1.0"), None);
        assert_eq!(service.total_records(), 1);
        assert_eq!(service.add_record("version", "1.1"), Some("1.0".to_owned()));
        assert_eq!(service.total_records(), 1);
        assert_eq!(service.add_record("entry_2", "2"), None);
        assert_eq!(service.total_records(), 2);
        assert_eq!(service.add_record("entry_3", "3"), None);
        assert_eq!(service.total_records(), 3);
        assert_eq!(service.add_record("entry_4", "4"), None);
        assert_eq!(service.total_records(), 4);
        assert_eq!(service.add_record("entry_5", "5"), None);
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
            Ok(["ValidName".to_owned()].to_vec())
        );
        assert_eq!(
            MdnsService::validate_instance_name("Another_Valid-Name"),
            Ok(["Another_Valid-Name".to_owned()].to_vec())
        );
        assert_eq!(
            MdnsService::validate_instance_name("One.Two.Three"),
            Ok(["One".to_owned(), "Two".to_owned(), "Three".to_owned()].to_vec())
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
            Ok(["_udp".to_owned()].to_vec())
        );
        assert_eq!(
            MdnsService::validate_service_type("_http._tcp"),
            Ok(["_http".to_owned(), "_tcp".to_owned()].to_vec())
        );
        assert_eq!(
            MdnsService::validate_service_type("_ftp._udp"),
            Ok(["_ftp".to_owned(), "_udp".to_owned()].to_vec())
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
        assert_eq!(MdnsService::validate_service_domain("validdomain"), Ok("validdomain".to_owned()));
        assert_eq!(MdnsService::validate_service_domain("another-valid_domain"), Ok("another-valid_domain".to_owned()));

        // Invalid service domains
        assert!(MdnsService::validate_service_domain("invalid.domain").is_err());
        assert!(MdnsService::validate_service_domain("invalid%domain").is_err());
        assert!(MdnsService::validate_service_domain("invalid\u{0000}domain").is_err());
    }
}