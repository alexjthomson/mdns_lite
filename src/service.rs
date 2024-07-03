use alloc::{string::String, vec::Vec};
use esp_idf_sys::esp_efuse_mac_get_default;
use heapless::FnvIndexMap;
use core::fmt::Write;

/// Defines errors that can occur when interacting with [`MdnsService`] or
/// [`MdnsTxtRecords`].
#[derive(Debug)]
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

/// A heapless mDNS TXT record storage that holds a maximum of `N` records.
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
pub struct MdnsTxtRecords<const N: usize> {
    records: FnvIndexMap<String, String, N>,
}

impl<const N: usize> Default for MdnsTxtRecords<N> {
    #[inline]
    #[must_use]
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> MdnsTxtRecords<N> {
    /// Creates a new, empty set of mDNS TXT records.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: FnvIndexMap::new(),
        }
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
pub struct MdnsService<const N: usize> {
    /// Name of the mDNS service.
    /// 
    /// This field stores the instance name of the mDNS service, which is a
    /// unique identifier for the specific instance of the service on the
    /// network. The instance name helps distinguish between multiple instances
    /// of the same service type.
    /// 
    /// ## Formatting
    /// The `name` should be a human-readable string that uniquely identifies
    /// the service instance within the local network. It should be descriptive
    /// enough to allow users to differentiate it from other services of the
    /// same type.
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
    name: String,
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
    txt_records: MdnsTxtRecords<N>,
}

impl<const N: usize> MdnsService<N> {
    /// Creates a new [`MdnsService`].
    #[inline(always)]
    #[must_use]
    pub fn new(
        name: &str,
        port: u16,
        txt_records: MdnsTxtRecords<N>,
    ) -> Self {
        Self {
            name: String::from(name),
            port,
            txt_records,
        }
    }

    /// Creates a new [`MdnsService`] with a more unique name.
    /// 
    /// This function takes in a `name_prefix`, which will be combined with a
    /// unique string of text generated from information about the device. This
    /// allows devices to be flashed with the same code, but each have unique
    /// names.
    /// 
    /// ## Example
    /// For example, if you are creating a motion sensor device, you might want
    /// the device to be called `motion_sensor`. This becomes a problem when you
    /// introduce more than one device. Using this function, you could create an
    /// mDNS service for the device with a unique name:
    /// 
    /// ```
    /// let service = MdnsService::new_with_unique_name(
    ///     "motion_sensor",
    ///     3000,
    ///     MdnsTxtRecords::new(),
    /// );
    /// ```
    #[must_use]
    pub fn new_with_unique_name(
        name_prefix: &str,
        port: u16,
        txt_records: MdnsTxtRecords<N>,
    ) -> Self {
        let mut mac: [u8; 6] = [0; 6];
        unsafe {
            esp_efuse_mac_get_default(mac.as_mut_ptr());
        }
        let mut unique_name = String::from(name_prefix);
        unique_name.push('_');
        for byte in mac {
            write!(&mut unique_name, "{:02x}", byte).unwrap();
        }
        Self {
            name: unique_name,
            port,
            txt_records,
        }
    }

    /// Returns the name of the [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn name(&self) -> &String {
        &self.name
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
    pub fn records(&self) -> &MdnsTxtRecords<N> {
        &self.txt_records
    }

    /// Returns a mutable reference to the underlying [`MdnsTxtRecords`] for the
    /// [`MdnsService`].
    #[inline]
    #[must_use]
    pub fn records_mut(&mut self) -> &mut MdnsTxtRecords<N> {
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