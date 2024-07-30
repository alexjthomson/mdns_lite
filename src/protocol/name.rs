use alloc::{
    string::{
        String,
        ToString,
    },
    vec::Vec,
};

/// Error type for [`MdnsName`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum MdnsNameError {
    // TODO: Document each error, why they occur, etc.
    MustEndWithDot,
    LabelTooShort,
    LabelTooLong,
    InvalidLabelLength {
        length: usize,
        max_length: usize,
    },
    InvalidUtf8Label,
    InvalidEndOfLabels,
    AllocError,
}

impl core::fmt::Display for MdnsNameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MustEndWithDot => write!(f, "DNS name must end with a `.`."),
            Self::LabelTooShort => write!(f, "Each label must contain at least 1 character."),
            Self::LabelTooLong => write!(f, "Each label must be 63 characters or less."),
            Self::InvalidLabelLength { length, max_length } => write!(
                f,
                "Label length exceeds data length `{length}` (maximum_length: `{max_length}`).",
            ),
            Self::InvalidUtf8Label => write!(f, "Label is not valid UTF-8."),
            Self::InvalidEndOfLabels => write!(f, "Labels do not end with a zero byte."),
            Self::AllocError => write!(f, "Failed to allocate memory to store the wire-format mDNS labels."),
        }
    }
}

/// Represents an mDNS name with its labels.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct MdnsName(Vec<u8>);

impl MdnsName {
    /// Maximum length of an individual label.
    /// 
    /// If this is exceeded, an [`MdnsNameError::LabelTooLong`] will be
    /// returned.
    pub const MAX_LABEL_LEN: usize = 63;

    /// Returns an empty [`MdnsName`] instance.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self([0x00].to_vec())
    }

    /// Creates a new [`MdnsName`].
    /// 
    /// ## Note
    /// Prefer using [`MdnsName::from_name`] since this function does not
    /// validate the `labels` provided to it.
    #[inline]
    #[must_use]
    pub fn new(labels: &[String]) -> Result<Self, MdnsNameError> {
        // Get the total number of labels that will make up the name.
        // Additionally, perform a zero-length check:
        let label_count: usize = labels.len();
        if label_count == 0 {
            // There are no labels that make up this name, therefore we should
            // return an empty instance:
            return Ok(Self::empty());
        }
        
        // Calculate the number of bytes that will make up the set of labels:
        // NOTE: We add `label_count` to the size since each label contains a
        // single byte to describe its size.
        let mut size: usize = label_count;
        for i in 0..label_count {
            // Get the length of the current label and validate its length:
            let label_size: usize = unsafe {
                // SAFETY: We know we are in range since we are only iterating
                // until `i`` reaches `label_count`:
                labels.get_unchecked(i).len()
            };
            if label_size == 0 {
                return Err(MdnsNameError::LabelTooShort);
            }
            if label_size > Self::MAX_LABEL_LEN {
                return Err(MdnsNameError::LabelTooLong);
            }
            // We can now include it in the total size:
            size += unsafe {
                // We know there are exactly `label_count` labels in `labels`:
                labels.get_unchecked(i).len()
            };
        }

        
        // Create a wire-format slice containing the labels:
        let mut bytes: Vec<u8> = Vec::with_capacity(size);
        let mut i: usize = 0;
        for label in labels {
            // Insert the length of the label:
            let len: usize = label.len();
            debug_assert!(bytes.len() - i >= len + 1);
            *unsafe {
                // SAFETY: `i` must be in range since we pre-calculated the size
                // of `bytes` to ensure it had the exact amount of space to
                // contain each of the labels:
                bytes.get_unchecked_mut(i)
            } = len as u8;
            i += 1;
            // Insert the label payload:
            if len > 0 {
                debug_assert!(label.is_ascii());
                let dst = unsafe {
                    // SAFETY: We pre-calculated the size of `bytes` to ensure
                    // it had the exact amount of space to contain each of the
                    // labels:
                    bytes.get_unchecked_mut(i..(i + len))
                };
                let src = label.as_bytes();
                unsafe {
                    // SAFETY: We pre-calculated the size of `bytes` to ensure
                    // it had the exact amount of space to contain each of the
                    // labels:
                    core::ptr::copy_nonoverlapping(
                        src.as_ptr(),
                        dst.as_mut_ptr(),
                        len,
                    );
                }
                i += len;
            }
        }
        Ok(Self(bytes))
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
        let mut labels = Vec::new();
        for label in name.trim_end_matches('.').split('.') {
            let len = label.len();
            if len == 0 {
                return Err(MdnsNameError::LabelTooShort);
            }
            if len > Self::MAX_LABEL_LEN {
                return Err(MdnsNameError::LabelTooLong);
            }
            labels.push(label.to_string());
        }
        MdnsName::new(&labels)
    }

    /// Create a [`MdnsName`] from wire format
    pub fn from_wire_format(data: &[u8], offset: &mut usize) -> Result<Self, MdnsNameError> {
        let mut labels = alloc::vec::Vec::<String>::new();
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
            let label = match core::str::from_utf8(&data[i..(i + len)]) {
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
        MdnsName::new(&labels)
    }

    /// Convert the [`MdnsName`] to its wire format
    #[inline]
    #[must_use]
    pub fn to_wire_format(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Display for MdnsName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut name = String::new();
        let name_len = self.0.len();
        let mut i: usize = 0;
        while i < self.0.len() {
            let len = *unsafe {
                // SAFETY: We just checked that `i` was in range.
                self.0.get_unchecked(i)
            } as usize;
            if len == 0 {
                // Reached end of DNS name.
                break;
            }
            i += 1;
            if name.is_empty() {
                name.push('.');
            }
            debug_assert!(i + len <= name_len);
            let label = unsafe {
                // SAFETY: We asserted that `i..(i+len)` was in range:
                self.0.get_unchecked(i..(i + len))
            };
            name.push_str(unsafe {
                // When creating an MdnsName, we ensure that labels are ASCII
                // only. ASCII can be converted directly to UTF-8:
                core::str::from_utf8_unchecked(label)
            });
            i += len;
        }
        write!(f, "{name}")
    }
}

impl TryFrom<Vec<String>> for MdnsName {
    type Error = MdnsNameError;
    fn try_from(labels: Vec<String>) -> Result<Self, Self::Error> {
        MdnsName::new(&labels)
    }
}

impl TryFrom<&[String]> for MdnsName {
    type Error = MdnsNameError;
    fn try_from(labels: &[String]) -> Result<Self, Self::Error> {
        MdnsName::new(labels)
    }
}

impl From<MdnsName> for Vec<String> {
    fn from(dns_name: MdnsName) -> Self {
        let mut labels = Vec::new();
        let name_len = dns_name.0.len();
        let mut i: usize = 0;
        while i < dns_name.0.len() {
            let len = *unsafe {
                // SAFETY: We just checked that `i` was in range.
                dns_name.0.get_unchecked(i)
            } as usize;
            if len == 0 {
                // Reached end of DNS name.
                break;
            }
            i += 1;
            debug_assert!(i + len <= name_len);
            let label = unsafe {
                // SAFETY: We asserted that `i..(i+len)` was in range:
                dns_name.0.get_unchecked(i..(i + len))
            };
            labels.push(unsafe {
                // When creating an MdnsName, we ensure that labels are ASCII
                // only. ASCII can be converted directly to UTF-8:
                core::str::from_utf8_unchecked(label)
            }.to_string());
            i += len;
        }
        labels
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

impl core::ops::Deref for MdnsName {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Achieve 100% test coverage.

    #[test]
    fn test_name_from_str() {
        let dns_name = MdnsName::from_name("example_service._http._tcp.local.").unwrap();
        assert_eq!(&dns_name.0, &[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            8, b's', b'e', b'r', b'v', b'i', b'c', b'e',
            5, b'_',
            4, b'h', b't', b't', b'p',
            4, b'_', 
            3, b't', b'c', b'p',
            5, b'l', b'o', b'c', b'a', b'l',
            0
        ]);
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
        assert_eq!(wire_format, &[
            15, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e',
            5, b'_', b'h', b't', b't', b'p',
            4, b'_', b't', b'c', b'p',
            5, b'l', b'o', b'c', b'a', b'l',
            0
        ]);
    }

    #[test]
    fn test_name_from_wire_format() {
        let wire_format = &[
            15, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e',
            5, b'_', b'h', b't', b't', b'p',
            4, b'_', b't', b'c', b'p',
            5, b'l', b'o', b'c', b'a', b'l',
            0
        ];
        let mut offset = 0;
        let dns_name = MdnsName::from_wire_format(wire_format, &mut offset).unwrap();
        assert_eq!(&dns_name.0, wire_format);
        assert_eq!(offset, wire_format.len());
    }

    #[test]
    fn test_name_from_invalid_wire_format() {
        let wire_format = &[
            15, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e',
            5, b'_', b'h', b't', b't', b'p',
            4, b'_', b't', b'c', b'p',
            5, b'l', b'o', b'c', b'a', b'l',
        ];
        let err = MdnsName::from_wire_format(wire_format, &mut 0).unwrap_err();
        assert_eq!(err, MdnsNameError::InvalidEndOfLabels);
    }
}