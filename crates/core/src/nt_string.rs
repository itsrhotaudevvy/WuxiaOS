//! Validation of NT native argument structures copied from user memory.
//!
//! The kernel copies a `UNICODE_STRING` or `OBJECT_ATTRIBUTES` out of user
//! space into a fixed-size byte array and decodes it here. Decoding never
//! dereferences the addresses it contains. It only checks that they describe
//! a plausible user range, so the kernel can copy exactly the bytes named.

use crate::paging::USER_ADDRESS_LIMIT;
use crate::{Error, Result};

/// Size in bytes of the x64 `UNICODE_STRING` structure.
pub const UNICODE_STRING_SIZE: usize = 16;

/// Size in bytes of the x64 `OBJECT_ATTRIBUTES` structure.
pub const OBJECT_ATTRIBUTES_SIZE: usize = 48;

/// Largest accepted `Length` of a name, in bytes.
pub const MAX_NAME_BYTES: u16 = 32766;

/// The handle is inherited by child processes.
pub const OBJ_INHERIT: u32 = 0x2;
/// The object survives the closure of its last handle.
pub const OBJ_PERMANENT: u32 = 0x10;
/// The object can be opened only for exclusive use.
pub const OBJ_EXCLUSIVE: u32 = 0x20;
/// Name lookup ignores ASCII case.
pub const OBJ_CASE_INSENSITIVE: u32 = 0x40;
/// Open the existing object if the name is already present.
pub const OBJ_OPENIF: u32 = 0x80;
/// Open a symbolic link object itself rather than its target.
pub const OBJ_OPENLINK: u32 = 0x100;
/// The handle is created in kernel mode.
pub const OBJ_KERNEL_HANDLE: u32 = 0x200;

/// Every attribute bit this implementation defines. Any other bit is rejected.
pub const OBJ_KNOWN_ATTRIBUTES: u32 = OBJ_INHERIT
    | OBJ_PERMANENT
    | OBJ_EXCLUSIVE
    | OBJ_CASE_INSENSITIVE
    | OBJ_OPENIF
    | OBJ_OPENLINK
    | OBJ_KERNEL_HANDLE;

/// A validated `UNICODE_STRING` whose code units live at a user address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnicodeString {
    /// User address of the first UTF-16 code unit. Not dereferenced when `length` is zero.
    pub buffer: u64,
    /// Number of bytes of UTF-16 data. Always even and at most [`MAX_NAME_BYTES`].
    pub length: u16,
}

impl UnicodeString {
    /// Decode and validate the 16-byte x64 `UNICODE_STRING` layout.
    ///
    /// Layout: `Length` (u16), `MaximumLength` (u16), padding, `Buffer` (u64).
    pub fn parse(bytes: &[u8; UNICODE_STRING_SIZE]) -> Result<Self> {
        let length = u16::from_le_bytes(field(bytes, 0));
        let maximum_length = u16::from_le_bytes(field(bytes, 2));
        let buffer = u64::from_le_bytes(field(bytes, 8));

        if !length.is_multiple_of(2) || !maximum_length.is_multiple_of(2) {
            return Err(Error::InvalidInput);
        }
        if length > maximum_length {
            return Err(Error::InvalidInput);
        }
        if length > MAX_NAME_BYTES {
            return Err(Error::InvalidName);
        }
        if length == 0 {
            return Ok(Self { buffer, length });
        }
        if buffer == 0 {
            return Err(Error::BadAddress);
        }
        let end = buffer
            .checked_add(u64::from(length))
            .ok_or(Error::OutOfRange)?;
        if end > USER_ADDRESS_LIMIT {
            return Err(Error::BadAddress);
        }
        Ok(Self { buffer, length })
    }

    /// Encode the 16-byte x64 `UNICODE_STRING` layout with the given `MaximumLength`.
    ///
    /// Applies the same rules as [`UnicodeString::parse`], so every encoded
    /// value decodes back to `self`.
    pub fn encode(&self, maximum_length: u16) -> Result<[u8; UNICODE_STRING_SIZE]> {
        let mut bytes = [0u8; UNICODE_STRING_SIZE];
        bytes[0..2].copy_from_slice(&self.length.to_le_bytes());
        bytes[2..4].copy_from_slice(&maximum_length.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.buffer.to_le_bytes());
        Self::parse(&bytes)?;
        Ok(bytes)
    }
}

/// A decoded x64 `OBJECT_ATTRIBUTES` with a validated attribute mask.
///
/// Address fields are returned unchecked. The kernel dereferences them, if
/// non-zero, through its own user-copy path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectAttributes {
    /// Handle of the directory that `object_name` is relative to, or zero.
    pub root_directory: u64,
    /// User address of the `UNICODE_STRING` naming the object, or zero for an unnamed object.
    pub object_name: u64,
    /// Validated `OBJ_*` flags, a subset of [`OBJ_KNOWN_ATTRIBUTES`].
    pub attributes: u32,
    /// User address of a security descriptor, or zero.
    pub security_descriptor: u64,
    /// User address of a security quality-of-service structure, or zero.
    pub security_qos: u64,
}

impl ObjectAttributes {
    /// Decode and validate the 48-byte x64 `OBJECT_ATTRIBUTES` layout.
    ///
    /// Layout: `Length` (u32, must be 48), padding, `RootDirectory` (u64),
    /// `ObjectName` (u64), `Attributes` (u32), padding, `SecurityDescriptor`
    /// (u64), `SecurityQoS` (u64).
    pub fn parse(bytes: &[u8; OBJECT_ATTRIBUTES_SIZE]) -> Result<Self> {
        let length = u32::from_le_bytes(field(bytes, 0));
        if length as usize != OBJECT_ATTRIBUTES_SIZE {
            return Err(Error::InvalidInput);
        }
        let attributes = u32::from_le_bytes(field(bytes, 24));
        if attributes & !OBJ_KNOWN_ATTRIBUTES != 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            root_directory: u64::from_le_bytes(field(bytes, 8)),
            object_name: u64::from_le_bytes(field(bytes, 16)),
            attributes,
            security_descriptor: u64::from_le_bytes(field(bytes, 32)),
            security_qos: u64::from_le_bytes(field(bytes, 40)),
        })
    }
}

/// Copy `N` bytes starting at `offset`. Callers pass fixed-size arrays and constant offsets.
fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&bytes[offset..offset + N]);
    out
}

/// Operations on NT names stored as UTF-16 code units.
pub trait Utf16Ascii {
    /// Compare two names, folding only ASCII letters `A`-`Z`.
    ///
    /// Non-ASCII code units compare exactly, so `É` and `é` are different names.
    fn eq_ignore_ascii_case(&self, other: &[u16]) -> bool;

    /// Convert an all-ASCII name into `out` and return it as `&str`.
    ///
    /// Fails with [`Error::InvalidName`] for any code unit above `0x7f`, which
    /// includes a NUL code unit. Surrogates are above that range, so unpaired
    /// surrogates are rejected as well. Fails with [`Error::OutOfRange`] when
    /// `out` is shorter than the name.
    fn to_ascii<'a>(&self, out: &'a mut [u8]) -> Result<&'a str>;
}

impl Utf16Ascii for [u16] {
    fn eq_ignore_ascii_case(&self, other: &[u16]) -> bool {
        self.len() == other.len()
            && self
                .iter()
                .zip(other)
                .all(|(&a, &b)| fold_ascii(a) == fold_ascii(b))
    }

    fn to_ascii<'a>(&self, out: &'a mut [u8]) -> Result<&'a str> {
        let out = out.get_mut(..self.len()).ok_or(Error::OutOfRange)?;
        for (dst, &unit) in out.iter_mut().zip(self) {
            *dst = u8::try_from(unit)
                .ok()
                .filter(|value| value.is_ascii() && *value != 0)
                .ok_or(Error::InvalidName)?;
        }
        core::str::from_utf8(out).map_err(|_| Error::InvalidName)
    }
}

const fn fold_ascii(unit: u16) -> u16 {
    match unit {
        0x41..=0x5a => unit + 0x20,
        _ => unit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unicode_bytes(length: u16, maximum_length: u16, buffer: u64) -> [u8; UNICODE_STRING_SIZE] {
        let mut bytes = [0u8; UNICODE_STRING_SIZE];
        bytes[0..2].copy_from_slice(&length.to_le_bytes());
        bytes[2..4].copy_from_slice(&maximum_length.to_le_bytes());
        bytes[8..16].copy_from_slice(&buffer.to_le_bytes());
        bytes
    }

    fn attribute_bytes(
        length: u32,
        root_directory: u64,
        object_name: u64,
        attributes: u32,
        security_descriptor: u64,
        security_qos: u64,
    ) -> [u8; OBJECT_ATTRIBUTES_SIZE] {
        let mut bytes = [0u8; OBJECT_ATTRIBUTES_SIZE];
        bytes[0..4].copy_from_slice(&length.to_le_bytes());
        bytes[8..16].copy_from_slice(&root_directory.to_le_bytes());
        bytes[16..24].copy_from_slice(&object_name.to_le_bytes());
        bytes[24..28].copy_from_slice(&attributes.to_le_bytes());
        bytes[32..40].copy_from_slice(&security_descriptor.to_le_bytes());
        bytes[40..48].copy_from_slice(&security_qos.to_le_bytes());
        bytes
    }

    #[test]
    fn unicode_string_decodes_little_endian_fields() {
        let bytes = [
            0x0a, 0x00, 0x0c, 0x00, 0, 0, 0, 0, 0x00, 0x10, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            UnicodeString::parse(&bytes),
            Ok(UnicodeString {
                buffer: 0x1000,
                length: 10,
            })
        );
    }

    #[test]
    fn unicode_string_accepts_empty_name_without_buffer() {
        assert_eq!(
            UnicodeString::parse(&unicode_bytes(0, 0, 0)),
            Ok(UnicodeString {
                buffer: 0,
                length: 0,
            })
        );
    }

    #[test]
    fn unicode_string_rejects_odd_byte_lengths() {
        assert_eq!(
            UnicodeString::parse(&unicode_bytes(3, 4, 0x1000)),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            UnicodeString::parse(&unicode_bytes(4, 5, 0x1000)),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn unicode_string_rejects_length_beyond_maximum() {
        assert_eq!(
            UnicodeString::parse(&unicode_bytes(8, 6, 0x1000)),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn unicode_string_enforces_the_name_bound() {
        assert_eq!(
            UnicodeString::parse(&unicode_bytes(MAX_NAME_BYTES, MAX_NAME_BYTES, 0x1000)),
            Ok(UnicodeString {
                buffer: 0x1000,
                length: MAX_NAME_BYTES,
            })
        );
        assert_eq!(
            UnicodeString::parse(&unicode_bytes(32768, 32768, 0x1000)),
            Err(Error::InvalidName)
        );
    }

    #[test]
    fn unicode_string_requires_a_buffer_for_characters() {
        assert_eq!(
            UnicodeString::parse(&unicode_bytes(2, 2, 0)),
            Err(Error::BadAddress)
        );
    }

    #[test]
    fn unicode_string_keeps_the_range_inside_user_space() {
        assert_eq!(
            UnicodeString::parse(&unicode_bytes(4, 4, USER_ADDRESS_LIMIT - 4)),
            Ok(UnicodeString {
                buffer: USER_ADDRESS_LIMIT - 4,
                length: 4,
            })
        );
        assert_eq!(
            UnicodeString::parse(&unicode_bytes(4, 4, USER_ADDRESS_LIMIT - 2)),
            Err(Error::BadAddress)
        );
        assert_eq!(
            UnicodeString::parse(&unicode_bytes(4, 4, u64::MAX - 1)),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn unicode_string_encode_round_trips_and_validates() {
        let name = UnicodeString {
            buffer: 0x2000,
            length: 6,
        };
        let bytes = name.encode(8).unwrap();
        assert_eq!(bytes, unicode_bytes(6, 8, 0x2000));
        assert_eq!(UnicodeString::parse(&bytes), Ok(name));
        assert_eq!(name.encode(4), Err(Error::InvalidInput));
        let unbacked = UnicodeString {
            buffer: 0,
            length: 2,
        };
        assert_eq!(unbacked.encode(2), Err(Error::BadAddress));
    }

    #[test]
    fn object_attributes_decode_every_field() {
        let bytes = attribute_bytes(
            48,
            0x11,
            0x2000,
            OBJ_CASE_INSENSITIVE | OBJ_INHERIT,
            0x3000,
            0x4000,
        );
        assert_eq!(
            ObjectAttributes::parse(&bytes),
            Ok(ObjectAttributes {
                root_directory: 0x11,
                object_name: 0x2000,
                attributes: OBJ_CASE_INSENSITIVE | OBJ_INHERIT,
                security_descriptor: 0x3000,
                security_qos: 0x4000,
            })
        );
    }

    #[test]
    fn object_attributes_accept_an_unnamed_object() {
        let parsed = ObjectAttributes::parse(&attribute_bytes(48, 0, 0, 0, 0, 0));
        assert_eq!(
            parsed,
            Ok(ObjectAttributes {
                root_directory: 0,
                object_name: 0,
                attributes: 0,
                security_descriptor: 0,
                security_qos: 0,
            })
        );
    }

    #[test]
    fn object_attributes_require_length_48() {
        for length in [0, 40, 47, 49, 56] {
            assert_eq!(
                ObjectAttributes::parse(&attribute_bytes(length, 0, 0, 0, 0, 0)),
                Err(Error::InvalidInput),
                "length {length}"
            );
        }
    }

    #[test]
    fn object_attributes_accept_each_defined_flag() {
        let flags = [
            OBJ_INHERIT,
            OBJ_PERMANENT,
            OBJ_EXCLUSIVE,
            OBJ_CASE_INSENSITIVE,
            OBJ_OPENIF,
            OBJ_OPENLINK,
            OBJ_KERNEL_HANDLE,
        ];
        assert_eq!(OBJ_KNOWN_ATTRIBUTES, 0x3f2);
        for flag in flags {
            let parsed = ObjectAttributes::parse(&attribute_bytes(48, 0, 0, flag, 0, 0));
            assert_eq!(parsed.map(|attrs| attrs.attributes), Ok(flag));
        }
    }

    #[test]
    fn object_attributes_reject_unknown_bits() {
        // 0x1 is OBJ_PROTECT_CLOSE, which this implementation does not define.
        for bit in [0x1, 0x4, 0x400, 0x800, 0x1000, 0x8000_0000] {
            assert_eq!(
                ObjectAttributes::parse(&attribute_bytes(48, 0, 0, bit, 0, 0)),
                Err(Error::InvalidInput),
                "bit {bit:#x}"
            );
        }
        assert_eq!(
            ObjectAttributes::parse(&attribute_bytes(48, 0, 0, OBJ_INHERIT | 0x1, 0, 0)),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn utf16_equality_folds_only_ascii_letters() {
        let wuxia = [0x57_u16, 0x75, 0x78, 0x69, 0x61];
        let shouting = [0x57_u16, 0x55, 0x58, 0x49, 0x41];
        assert!(wuxia.as_slice().eq_ignore_ascii_case(&shouting));
        assert!(!wuxia.as_slice().eq_ignore_ascii_case(&wuxia[..4]));

        // 0x5a is 'Z' and 0x7a is 'z'. The code units between them, such as '[' and '{', are not letters.
        assert!([0x5a_u16].as_slice().eq_ignore_ascii_case(&[0x7a]));
        assert!(![0x5b_u16].as_slice().eq_ignore_ascii_case(&[0x7b]));
        assert!(![0x40_u16].as_slice().eq_ignore_ascii_case(&[0x60]));

        let e_acute_upper = [0xc9_u16];
        let e_acute_lower = [0xe9_u16];
        assert!(
            !e_acute_upper
                .as_slice()
                .eq_ignore_ascii_case(&e_acute_lower)
        );
    }

    #[test]
    fn utf16_converts_ascii_names() {
        let units = [0x57_u16, 0x75, 0x78, 0x69, 0x61];
        let mut buffer = [0u8; 8];
        assert_eq!(units.as_slice().to_ascii(&mut buffer), Ok("Wuxia"));

        let mut empty = [0u8; 0];
        assert_eq!([0u16; 0].as_slice().to_ascii(&mut empty), Ok(""));
    }

    #[test]
    fn utf16_to_ascii_rejects_non_ascii_units() {
        let mut buffer = [0u8; 4];
        assert_eq!(
            [0x41_u16, 0xe9].as_slice().to_ascii(&mut buffer),
            Err(Error::InvalidName)
        );
        assert_eq!(
            [0x80_u16].as_slice().to_ascii(&mut buffer),
            Err(Error::InvalidName)
        );
    }

    #[test]
    fn utf16_to_ascii_rejects_surrogates() {
        let mut buffer = [0u8; 4];
        // A valid pair (U+1F600) is still non-ASCII.
        assert_eq!(
            [0xd83d_u16, 0xde00].as_slice().to_ascii(&mut buffer),
            Err(Error::InvalidName)
        );
        // An unpaired high surrogate after an ASCII unit.
        assert_eq!(
            [0x41_u16, 0xd800].as_slice().to_ascii(&mut buffer),
            Err(Error::InvalidName)
        );
    }

    #[test]
    fn utf16_to_ascii_checks_output_capacity() {
        let mut buffer = [0u8; 1];
        assert_eq!(
            [0x41_u16, 0x42].as_slice().to_ascii(&mut buffer),
            Err(Error::OutOfRange)
        );
    }
}
