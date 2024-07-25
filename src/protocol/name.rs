use thiserror::Error;

/// Error type for [`MdnsName`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Error, Debug)]
pub enum MdnsNameError {
    #[error("DNS name must end with a `.`.")]
    MustEndWithDot,
    #[error("Each label must be 63 characters or less.")]
    LabelTooLong,
    #[error("Label length exceeds data length `{length}` (maximum_length: `{max_length}`).")]
    InvalidLabelLength {
        length: usize,
        max_length: usize,
    },
    #[error("Label is not valid UTF-8.")]
    InvalidUtf8Label,
    #[error("Labels do not end with a zero byte.")]
    InvalidEndOfLabels,
}

/// Represents an mDNS name with its labels.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct MdnsName {
    /// Labels that make up the [`MdnsName`].
    labels: Vec<String>,
}

impl MdnsName {
    /// Creates a new [`MdnsName`].
    /// 
    /// ## Note
    /// Prefer using [`MdnsName::from_name`] since this function does not
    /// validate the `labels` provided to it.
    #[inline]
    #[must_use]
    pub fn new(labels: Vec<String>) -> Self {
        Self { labels }
    }

    /// Creates a new [`MdnsName`] from a string representation of the name.
    /// 
    /// The string representation should be formatted as follows:
    /// `instance_name._service_type_name._service_type_protocol.service_domain.`,
    /// and may contain any number of labels. The string must end with a dot and
    /// only contain alphanumeric characters, hyphens, and underscores.
    pub fn from_name(name: &str) -> Result<Self, MdnsNameError> {
        if name.is_empty() || !name.ends_with('.') {
            return Err(MdnsNameError::MustEndWithDot);
        }
        let labels: Vec<String> = name
            .trim_end_matches('.')
            .split('.')
            .map(|s| s.to_string())
            .collect();

        for label in &labels {
            if label.len() > 63 {
                return Err(MdnsNameError::LabelTooLong);
            }
        }
        Ok(MdnsName::new(labels))
    }

    /// Convert the [`MdnsName`] to its wire format
    #[must_use]
    pub fn to_wire_format(&self) -> Vec<u8> {
        let mut wire_format = Vec::new();
        for label in &self.labels {
            debug_assert!(label.is_ascii());
            wire_format.push(label.len() as u8);
            wire_format.extend_from_slice(label.as_bytes());
        }
        wire_format.push(0); // End of name
        wire_format
    }

    /// Create a [`MdnsName`] from wire format
    pub fn from_wire_format(data: &[u8], offset: &mut usize) -> Result<Self, MdnsNameError> {
        let mut labels = Vec::new();
        let mut i: usize = *offset;
        while i < data.len() {
            // Get the length of the next label:
            let len: usize = data[i] as usize;

            // Check for a null byte, this indicates that this is the end of the
            // wire format labels. We should therefore stop here:
            if len == 0 {
                break;
            }

            // We should iterate the offset by `1` since we just read the label
            // length byte and it was not a null byte:
            i += 1;

            // We need to perform a range check to ensure that the `data` buffer
            // has enough space to contain the label:
            if i + len > data.len() {
                return Err(MdnsNameError::InvalidLabelLength {
                    length: len,
                    max_length: data.len() - i,
                });
            }

            // Read the label from the `data` buffer:
            let label = match std::str::from_utf8(&data[i..(i + len)]) {
                Ok(label) => label.to_string(),
                Err(_) => return Err(MdnsNameError::InvalidUtf8Label),
            };

            // We can now push the constructed label to the `labels` vector:
            labels.push(label);

            // We also need to move the offset to the start of the next label:
            i += len;
        }
        if i == data.len() || data[i] != 0 {
            return Err(MdnsNameError::InvalidEndOfLabels);
        }
        *offset = i + 1;
        Ok(MdnsName { labels })
    }
}

impl std::fmt::Display for MdnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.", self.labels.join("."))
    }
}

impl From<Vec<String>> for MdnsName {
    fn from(labels: Vec<String>) -> Self {
        MdnsName::new(labels)
    }
}

impl From<MdnsName> for Vec<String> {
    fn from(dns_name: MdnsName) -> Self {
        dns_name.labels
    }
}

impl TryFrom<&str> for MdnsName {
    type Error = MdnsNameError;
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        MdnsName::from_name(name)
    }
}

impl TryFrom<String> for MdnsName {
    type Error = MdnsNameError;
    fn try_from(name: String) -> Result<Self, Self::Error> {
        MdnsName::from_name(name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Achieve 100% test coverage.

    #[test]
    fn test_name_from_str() {
        let dns_name = MdnsName::from_name("example_service._http._tcp.local.").unwrap();
        assert_eq!(dns_name.labels, vec!["example_service", "_http", "_tcp", "local"]);
    }

    #[test]
    fn test_name_from_invalid_str() {
        let err = MdnsName::from_name("example_service._http._tcp.local").unwrap_err();
        assert_eq!(err, MdnsNameError::MustEndWithDot);
    }

    #[test]
    fn test_name_from_long_label_str() {
        let mut label = "a".repeat(64);
        label.push('.');
        let err = MdnsName::from_name(label.as_str()).unwrap_err();
        assert_eq!(err, MdnsNameError::LabelTooLong);
    }

    #[test]
    fn test_name_to_wire_format() {
        let dns_name = MdnsName::from_name("example_service._http._tcp.local.").unwrap();
        let wire_format = dns_name.to_wire_format();
        assert_eq!(wire_format, vec![
            15, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e',
            5, b'_', b'h', b't', b't', b'p',
            4, b'_', b't', b'c', b'p',
            5, b'l', b'o', b'c', b'a', b'l',
            0
        ]);
    }

    #[test]
    fn test_name_from_wire_format() {
        let wire_format = vec![
            15, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e',
            5, b'_', b'h', b't', b't', b'p',
            4, b'_', b't', b'c', b'p',
            5, b'l', b'o', b'c', b'a', b'l',
            0
        ];
        let mut offset = 0;
        let dns_name = MdnsName::from_wire_format(&wire_format, &mut offset).unwrap();
        assert_eq!(dns_name.labels, vec!["example_service", "_http", "_tcp", "local"]);
        assert_eq!(offset, wire_format.len());
    }

    #[test]
    fn test_name_from_invalid_wire_format() {
        let wire_format = vec![
            15, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e',
            5, b'_', b'h', b't', b't', b'p',
            4, b'_', b't', b'c', b'p',
            5, b'l', b'o', b'c', b'a', b'l',
        ];
        let err = MdnsName::from_wire_format(&wire_format, &mut 0).unwrap_err();
        assert_eq!(err, MdnsNameError::InvalidEndOfLabels);
    }
}