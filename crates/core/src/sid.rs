//! NT security identifiers (SIDs): binary and textual forms, well-known
//! constants, and domain-prefix comparison.
//!
//! Only revision 1 exists. The identifier authority is 48 bits wide and is
//! stored big-endian in the binary form; sub-authorities are little-endian
//! `u32` values. The text form is `S-1-<authority>-<sub>...`, where an
//! authority of 2^32 or more is written in hex as `0x` followed by twelve
//! digits, as Windows does.

use crate::{Error, Result};

/// The only SID revision in existence.
const REVISION: u8 = 1;
/// Revision, sub-authority count and the six authority bytes.
const HEADER_LENGTH: usize = 8;
/// Each sub-authority is a little-endian `u32`.
const SUBAUTHORITY_LENGTH: usize = 4;
/// Largest number of sub-authorities a SID may carry.
pub const MAX_SUBAUTHORITIES: usize = 15;
/// Largest identifier authority, which is 48 bits wide.
pub const MAX_AUTHORITY: u64 = (1 << 48) - 1;
/// Largest encoded size of a SID, in bytes.
pub const MAX_BINARY_LENGTH: usize = HEADER_LENGTH + SUBAUTHORITY_LENGTH * MAX_SUBAUTHORITIES;
/// Largest length of a formatted SID, in bytes.
///
/// `S-1-` (4) plus a hex authority (14) plus fifteen `-` and ten-digit
/// sub-authorities (165).
pub const MAX_TEXT_LENGTH: usize = 4 + 14 + 15 * 11;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// A security identifier with at most [`MAX_SUBAUTHORITIES`] sub-authorities.
///
/// Unused sub-authority slots are always zero, so the derived equality
/// compares exactly the identifier's contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sid {
    authority: u64,
    count: u8,
    subauthorities: [u32; MAX_SUBAUTHORITIES],
}

/// `S-1-0-0`: the null SID.
pub const NULL: Sid = Sid::from_parts(0, &[0]);
/// `S-1-1-0`: the Everyone group.
pub const WORLD: Sid = Sid::from_parts(1, &[0]);
/// `S-1-5-18`: the local system account.
pub const LOCAL_SYSTEM: Sid = Sid::from_parts(5, &[18]);
/// `S-1-5-19`: the local service account.
pub const LOCAL_SERVICE: Sid = Sid::from_parts(5, &[19]);
/// `S-1-5-20`: the network service account.
pub const NETWORK_SERVICE: Sid = Sid::from_parts(5, &[20]);
/// `S-1-5-32-544`: the built-in Administrators group.
pub const BUILTIN_ADMINISTRATORS: Sid = Sid::from_parts(5, &[32, 544]);
/// `S-1-5-32-545`: the built-in Users group.
pub const BUILTIN_USERS: Sid = Sid::from_parts(5, &[32, 545]);

impl Sid {
    /// Build a SID from an authority and sub-authorities.
    pub const fn new(authority: u64, subauthorities: &[u32]) -> Result<Self> {
        if authority > MAX_AUTHORITY || subauthorities.len() > MAX_SUBAUTHORITIES {
            return Err(Error::OutOfRange);
        }
        Ok(Self::from_parts(authority, subauthorities))
    }

    /// Build a SID whose arguments the caller has already validated.
    const fn from_parts(authority: u64, subauthorities: &[u32]) -> Self {
        let mut stored = [0u32; MAX_SUBAUTHORITIES];
        let mut index = 0;
        while index < subauthorities.len() {
            stored[index] = subauthorities[index];
            index += 1;
        }
        Self {
            authority,
            count: subauthorities.len() as u8,
            subauthorities: stored,
        }
    }

    /// The 48-bit identifier authority.
    pub const fn authority(&self) -> u64 {
        self.authority
    }

    /// The sub-authorities in order.
    pub fn subauthorities(&self) -> &[u32] {
        &self.subauthorities[..usize::from(self.count)]
    }

    /// Number of bytes [`Sid::write_binary`] produces.
    pub const fn binary_len(&self) -> usize {
        HEADER_LENGTH + SUBAUTHORITY_LENGTH * self.count as usize
    }

    /// Decode a binary SID from the start of `bytes`.
    ///
    /// Returns the SID and the number of bytes it occupies. Trailing bytes
    /// are left untouched.
    pub fn parse_binary(bytes: &[u8]) -> Result<(Self, usize)> {
        let header = bytes
            .first_chunk::<HEADER_LENGTH>()
            .ok_or(Error::InvalidInput)?;
        if header[0] != REVISION {
            return Err(Error::InvalidInput);
        }
        let count = usize::from(header[1]);
        if count > MAX_SUBAUTHORITIES {
            return Err(Error::OutOfRange);
        }
        let length = HEADER_LENGTH + SUBAUTHORITY_LENGTH * count;
        let encoded = bytes.get(..length).ok_or(Error::InvalidInput)?;

        let authority = header[2..HEADER_LENGTH]
            .iter()
            .fold(0u64, |value, &byte| (value << 8) | u64::from(byte));

        let (encoded_subauthorities, _) =
            encoded[HEADER_LENGTH..].as_chunks::<SUBAUTHORITY_LENGTH>();
        let mut subauthorities = [0u32; MAX_SUBAUTHORITIES];
        for (slot, raw) in subauthorities.iter_mut().zip(encoded_subauthorities) {
            *slot = u32::from_le_bytes(*raw);
        }

        let sid = Self::new(authority, &subauthorities[..count])?;
        Ok((sid, length))
    }

    /// Encode the SID into the start of `out`, returning the bytes written.
    pub fn write_binary(&self, out: &mut [u8]) -> Result<usize> {
        let length = self.binary_len();
        let encoded = out.get_mut(..length).ok_or(Error::OutOfRange)?;
        encoded[0] = REVISION;
        encoded[1] = self.count;
        let authority = self.authority.to_be_bytes();
        encoded[2..HEADER_LENGTH].copy_from_slice(&authority[2..]);
        let (encoded_subauthorities, _) =
            encoded[HEADER_LENGTH..].as_chunks_mut::<SUBAUTHORITY_LENGTH>();
        for (chunk, subauthority) in encoded_subauthorities.iter_mut().zip(self.subauthorities()) {
            *chunk = subauthority.to_le_bytes();
        }
        Ok(length)
    }

    /// Parse the text form, such as `S-1-5-21-1-2-3-500`.
    ///
    /// Each field is ASCII digits only; a leading `+`, an empty field or an
    /// overflowing value is rejected. An authority may also be written as
    /// `0x` followed by hex digits.
    pub fn parse_str(text: &str) -> Result<Self> {
        let mut fields = text.split('-');
        if fields.next() != Some("S") {
            return Err(Error::InvalidInput);
        }
        let revision = parse_number(fields.next().ok_or(Error::InvalidInput)?, 10, u64::MAX)?;
        if revision != u64::from(REVISION) {
            return Err(Error::InvalidInput);
        }
        let authority = parse_authority(fields.next().ok_or(Error::InvalidInput)?)?;

        let mut subauthorities = [0u32; MAX_SUBAUTHORITIES];
        let mut count = 0;
        for field in fields {
            if count == MAX_SUBAUTHORITIES {
                return Err(Error::OutOfRange);
            }
            let value = parse_number(field, 10, u64::from(u32::MAX))?;
            subauthorities[count] = u32::try_from(value).map_err(|_| Error::OutOfRange)?;
            count += 1;
        }
        Self::new(authority, &subauthorities[..count])
    }

    /// Write the text form into `out` and return it as a string slice.
    ///
    /// `out` needs at least [`MAX_TEXT_LENGTH`] bytes to hold any SID.
    pub fn format<'a>(&self, out: &'a mut [u8]) -> Result<&'a str> {
        let mut text = TextWriter { out, length: 0 };
        text.push(b"S-1-")?;
        if self.authority <= u64::from(u32::MAX) {
            text.push_decimal(self.authority)?;
        } else {
            text.push(b"0x")?;
            for &byte in &self.authority.to_be_bytes()[2..] {
                text.push_hex_byte(byte)?;
            }
        }
        for &subauthority in self.subauthorities() {
            text.push(b"-")?;
            text.push_decimal(u64::from(subauthority))?;
        }
        let length = text.length;
        let written: &'a [u8] = text.out;
        core::str::from_utf8(&written[..length]).map_err(|_| Error::InvalidState)
    }

    /// Whether `prefix` is this SID's domain: an equal authority and leading
    /// sub-authorities. A SID is a prefix of itself.
    pub fn has_prefix(&self, prefix: &Sid) -> bool {
        self.authority == prefix.authority
            && self.subauthorities().starts_with(prefix.subauthorities())
    }
}

/// Parse an unsigned decimal or, with a `0x` prefix, hexadecimal authority.
fn parse_authority(field: &str) -> Result<u64> {
    if let Some(hex) = field
        .strip_prefix("0x")
        .or_else(|| field.strip_prefix("0X"))
    {
        parse_number(hex, 16, MAX_AUTHORITY)
    } else {
        parse_number(field, 10, MAX_AUTHORITY)
    }
}

/// Parse digits in `radix`, rejecting empty input, non-digits (including
/// `+`) and any value above `max`.
fn parse_number(digits: &str, radix: u32, max: u64) -> Result<u64> {
    if digits.is_empty() {
        return Err(Error::InvalidInput);
    }
    let mut value = 0u64;
    for ch in digits.chars() {
        let digit = ch.to_digit(radix).ok_or(Error::InvalidInput)?;
        value = value
            .checked_mul(u64::from(radix))
            .and_then(|scaled| scaled.checked_add(u64::from(digit)))
            .ok_or(Error::OutOfRange)?;
        if value > max {
            return Err(Error::OutOfRange);
        }
    }
    Ok(value)
}

/// Appends ASCII text to a caller-provided buffer, refusing to overflow it.
struct TextWriter<'a> {
    out: &'a mut [u8],
    length: usize,
}

impl TextWriter<'_> {
    fn push(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .length
            .checked_add(bytes.len())
            .ok_or(Error::OutOfRange)?;
        let destination = self
            .out
            .get_mut(self.length..end)
            .ok_or(Error::OutOfRange)?;
        destination.copy_from_slice(bytes);
        self.length = end;
        Ok(())
    }

    fn push_decimal(&mut self, mut value: u64) -> Result<()> {
        let mut digits = [0u8; 20];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push(&digits[start..])
    }

    fn push_hex_byte(&mut self, byte: u8) -> Result<()> {
        self.push(&[
            HEX_DIGITS[usize::from(byte >> 4)],
            HEX_DIGITS[usize::from(byte & 0x0f)],
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(text: &str) -> Sid {
        Sid::parse_str(text).unwrap()
    }

    /// Format `value` and compare the result with `expected`.
    fn assert_text(value: &Sid, expected: &str) {
        let mut buffer = [0u8; MAX_TEXT_LENGTH];
        assert_eq!(value.format(&mut buffer), Ok(expected));
    }

    #[test]
    fn well_known_constants_have_their_standard_text_forms() {
        assert_text(&NULL, "S-1-0-0");
        assert_text(&WORLD, "S-1-1-0");
        assert_text(&LOCAL_SYSTEM, "S-1-5-18");
        assert_text(&LOCAL_SERVICE, "S-1-5-19");
        assert_text(&NETWORK_SERVICE, "S-1-5-20");
        assert_text(&BUILTIN_ADMINISTRATORS, "S-1-5-32-544");
        assert_text(&BUILTIN_USERS, "S-1-5-32-545");
    }

    #[test]
    fn well_known_constants_parse_to_the_same_values() {
        assert_eq!(sid("S-1-0-0"), NULL);
        assert_eq!(sid("S-1-1-0"), WORLD);
        assert_eq!(sid("S-1-5-18"), LOCAL_SYSTEM);
        assert_eq!(sid("S-1-5-19"), LOCAL_SERVICE);
        assert_eq!(sid("S-1-5-20"), NETWORK_SERVICE);
        assert_eq!(sid("S-1-5-32-544"), BUILTIN_ADMINISTRATORS);
        assert_eq!(sid("S-1-5-32-545"), BUILTIN_USERS);
    }

    #[test]
    fn binary_layout_is_big_endian_authority_and_little_endian_subauthorities() {
        let value = Sid::new(0x0102_0304_0506, &[0x1122_3344]).unwrap();
        let mut buffer = [0xffu8; 16];
        assert_eq!(value.write_binary(&mut buffer), Ok(12));
        assert_eq!(
            buffer[..12],
            [1, 1, 1, 2, 3, 4, 5, 6, 0x44, 0x33, 0x22, 0x11]
        );
        assert_eq!(buffer[12..], [0xff; 4]);
    }

    #[test]
    fn binary_round_trips_for_constants_and_maximal_sids() {
        let maximal = Sid::new(MAX_AUTHORITY, &[u32::MAX; MAX_SUBAUTHORITIES]).unwrap();
        for original in [
            NULL,
            WORLD,
            LOCAL_SYSTEM,
            BUILTIN_ADMINISTRATORS,
            BUILTIN_USERS,
            maximal,
        ] {
            let mut buffer = [0u8; MAX_BINARY_LENGTH];
            let written = original.write_binary(&mut buffer).unwrap();
            assert_eq!(written, original.binary_len());
            assert_eq!(
                Sid::parse_binary(&buffer[..written]),
                Ok((original, written))
            );
        }
    }

    #[test]
    fn parse_binary_reports_consumed_length_and_ignores_trailing_bytes() {
        let mut buffer = [0u8; 20];
        let written = BUILTIN_USERS.write_binary(&mut buffer).unwrap();
        buffer[written..].fill(0xee);
        assert_eq!(Sid::parse_binary(&buffer), Ok((BUILTIN_USERS, 16)));
    }

    #[test]
    fn parse_binary_rejects_other_revisions_truncation_and_excess_counts() {
        let mut encoded = [0u8; 12];
        LOCAL_SYSTEM.write_binary(&mut encoded).unwrap();

        let mut revision_two = encoded;
        revision_two[0] = 2;
        assert_eq!(Sid::parse_binary(&revision_two), Err(Error::InvalidInput));

        assert_eq!(Sid::parse_binary(&encoded[..11]), Err(Error::InvalidInput));
        assert_eq!(Sid::parse_binary(&encoded[..7]), Err(Error::InvalidInput));
        assert_eq!(Sid::parse_binary(&[]), Err(Error::InvalidInput));

        let mut sixteen = [0u8; 72];
        sixteen[0] = 1;
        sixteen[1] = 16;
        assert_eq!(Sid::parse_binary(&sixteen), Err(Error::OutOfRange));
    }

    #[test]
    fn write_binary_refuses_a_short_buffer_without_writing() {
        let mut buffer = [0xaau8; 11];
        assert_eq!(
            LOCAL_SYSTEM.write_binary(&mut buffer),
            Err(Error::OutOfRange)
        );
        assert_eq!(buffer, [0xaa; 11]);
    }

    #[test]
    fn string_round_trips_preserve_the_text() {
        for text in [
            "S-1-0-0",
            "S-1-5-21-1004336348-1177238915-682003330-512",
            "S-1-5-32-544",
            "S-1-5-80-1-2-3-4-5-6-7-8-9-10-11-12-13-14",
            "S-1-4294967295-4294967295",
            "S-1-0x000100000000-1",
            "S-1-0xffffffffffff-0",
        ] {
            let parsed = sid(text);
            assert_text(&parsed, text);
            let mut binary = [0u8; MAX_BINARY_LENGTH];
            let written = parsed.write_binary(&mut binary).unwrap();
            assert_eq!(Sid::parse_binary(&binary[..written]), Ok((parsed, written)));
        }
    }

    #[test]
    fn authorities_are_hex_from_two_to_the_thirty_two_upwards() {
        assert_text(
            &Sid::new(u64::from(u32::MAX), &[]).unwrap(),
            "S-1-4294967295",
        );
        assert_text(&Sid::new(1 << 32, &[]).unwrap(), "S-1-0x000100000000");
        assert_text(&Sid::new(MAX_AUTHORITY, &[]).unwrap(), "S-1-0xffffffffffff");
        // A decimal spelling above 32 bits parses, but formats in hex.
        assert_eq!(sid("S-1-4294967296-1"), sid("S-1-0x000100000000-1"));
        assert_eq!(sid("S-1-0x0000000000ff-7"), sid("S-1-255-7"));
    }

    #[test]
    fn parse_str_rejects_empty_fields_and_missing_components() {
        for text in [
            "", "S", "S-", "S-1", "S-1-", "S-1--5", "S-1-5-", "S-1-5--3", "S--5", "S-1-0x-5",
        ] {
            assert_eq!(Sid::parse_str(text), Err(Error::InvalidInput), "{text:?}");
        }
    }

    #[test]
    fn parse_str_rejects_a_leading_plus_in_every_field() {
        for text in ["S-+1-5", "S-1-+5", "S-1-5-+21", "S-1-0x+5", "S-1-5-21-+1"] {
            assert_eq!(Sid::parse_str(text), Err(Error::InvalidInput), "{text:?}");
        }
    }

    #[test]
    fn parse_str_rejects_overflow_and_out_of_range_values() {
        assert_eq!(Sid::parse_str("S-1-5-4294967296"), Err(Error::OutOfRange));
        assert_eq!(
            Sid::parse_str("S-1-0x1000000000000"),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            Sid::parse_str("S-1-281474976710656"),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            Sid::parse_str("S-1-99999999999999999999999999"),
            Err(Error::OutOfRange)
        );
        let sixteen = "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16";
        assert_eq!(Sid::parse_str(sixteen), Err(Error::OutOfRange));
    }

    #[test]
    fn parse_str_rejects_wrong_prefix_and_other_revisions() {
        for text in ["X-1-5-18", "s-1-5-18", "S-2-5-18", "S-0-5-18", "S-01x-5"] {
            assert_eq!(Sid::parse_str(text), Err(Error::InvalidInput), "{text:?}");
        }
    }

    #[test]
    fn format_refuses_short_buffers_and_fits_the_maximal_text() {
        let maximal = Sid::new(MAX_AUTHORITY, &[u32::MAX; MAX_SUBAUTHORITIES]).unwrap();
        let mut exact = [0u8; MAX_TEXT_LENGTH];
        assert!(maximal.format(&mut exact).unwrap().len() <= MAX_TEXT_LENGTH);

        // "S-1-5-18" is eight bytes and "S-1-5-32-544" is twelve.
        let mut short = [0u8; 7];
        assert_eq!(LOCAL_SYSTEM.format(&mut short), Err(Error::OutOfRange));
        let mut tight = [0u8; 11];
        assert_eq!(
            BUILTIN_ADMINISTRATORS.format(&mut tight),
            Err(Error::OutOfRange)
        );
        let mut exact = [0u8; 8];
        assert_eq!(LOCAL_SYSTEM.format(&mut exact), Ok("S-1-5-18"));
    }

    #[test]
    fn equality_compares_authority_count_and_every_subauthority() {
        assert_eq!(sid("S-1-5-21-1-2-3"), sid("S-1-5-21-1-2-3"));
        assert_ne!(sid("S-1-5-21-1-2-3"), sid("S-1-5-21-1-2-4"));
        assert_ne!(sid("S-1-5-21-1-2"), sid("S-1-5-21-1-2-0"));
        assert_ne!(sid("S-1-5-18"), sid("S-1-4-18"));
    }

    #[test]
    fn has_prefix_matches_whole_leading_subauthorities_only() {
        let domain = sid("S-1-5-21-1-2-3");
        assert!(sid("S-1-5-21-1-2-3-500").has_prefix(&domain));
        assert!(domain.has_prefix(&domain));
        assert!(!domain.has_prefix(&sid("S-1-5-21-1-2-3-500")));
        assert!(!sid("S-1-5-21-1-2-4-500").has_prefix(&domain));
        assert!(!sid("S-1-5-21-1-2-30").has_prefix(&domain));
        assert!(!sid("S-1-5-32-544").has_prefix(&domain));
        assert!(!sid("S-1-6-21-1-2-3-500").has_prefix(&domain));
        assert!(!sid("S-1-5-32-544").has_prefix(&NULL));
    }
}
