//! NT access masks, binary ACLs and the discretionary access check.
//!
//! ACL bytes come from untrusted sources. [`Acl::parse`] validates the whole
//! structure up front, so every ACE produced later is well formed. SIDs are
//! opaque byte slices here; only their framing is checked.

use crate::{Error, Result};

/// Delete the object.
pub const DELETE: u32 = 0x0001_0000;
/// Read the security descriptor.
pub const READ_CONTROL: u32 = 0x0002_0000;
/// Modify the discretionary ACL.
pub const WRITE_DAC: u32 = 0x0004_0000;
/// Change the owner.
pub const WRITE_OWNER: u32 = 0x0008_0000;
/// Wait on or synchronize with the object.
pub const SYNCHRONIZE: u32 = 0x0010_0000;
/// Request the maximal set of rights the caller is granted.
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// Generic: all rights.
pub const GENERIC_ALL: u32 = 0x1000_0000;
/// Generic: execute rights.
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
/// Generic: write rights.
pub const GENERIC_WRITE: u32 = 0x4000_0000;
/// Generic: read rights.
pub const GENERIC_READ: u32 = 0x8000_0000;

const GENERIC_BITS: u32 = GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;

/// Bits a `MAXIMUM_ALLOWED` request can report: object-specific and standard
/// rights. `ACCESS_SYSTEM_SECURITY` (bit 24) is excluded because it requires a
/// privilege this module does not model.
pub const GRANTABLE_RIGHTS: u32 = 0x00ff_ffff;

/// Object-specific mapping of the four generic rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericMapping {
    /// Specific rights that `GENERIC_READ` expands to.
    pub read: u32,
    /// Specific rights that `GENERIC_WRITE` expands to.
    pub write: u32,
    /// Specific rights that `GENERIC_EXECUTE` expands to.
    pub execute: u32,
    /// Specific rights that `GENERIC_ALL` expands to.
    pub all: u32,
}

/// Replace generic bits in `mask` with the specific rights they map to.
///
/// Non-generic bits, including `MAXIMUM_ALLOWED`, pass through unchanged.
pub const fn map_generic(mask: u32, mapping: &GenericMapping) -> u32 {
    let mut mapped = mask & !GENERIC_BITS;
    if mask & GENERIC_READ != 0 {
        mapped |= mapping.read;
    }
    if mask & GENERIC_WRITE != 0 {
        mapped |= mapping.write;
    }
    if mask & GENERIC_EXECUTE != 0 {
        mapped |= mapping.execute;
    }
    if mask & GENERIC_ALL != 0 {
        mapped |= mapping.all;
    }
    mapped
}

/// ACL revision for the basic ACE set.
pub const ACL_REVISION: u8 = 2;
/// ACL revision that permits object ACEs.
pub const ACL_REVISION_DS: u8 = 4;
/// `AceType` of an access-allowed ACE.
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// `AceType` of an access-denied ACE.
pub const ACCESS_DENIED_ACE_TYPE: u8 = 1;
/// `AceFlags` bit marking an ACE that applies only to inheritors.
pub const INHERIT_ONLY_ACE: u8 = 0x08;

const ACL_HEADER_LEN: usize = 8;
const ACE_HEADER_LEN: usize = 8;
const SID_REVISION: u8 = 1;
const SID_MAX_SUBAUTHORITIES: u8 = 15;

/// The effect of an access-control entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AceKind {
    /// Grants the masked rights to matching SIDs.
    Allowed,
    /// Denies the masked rights to matching SIDs.
    Denied,
}

/// A decoded access-allowed or access-denied entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ace<'a> {
    /// Whether the entry grants or denies.
    pub kind: AceKind,
    /// The raw `AceFlags` byte.
    pub flags: u8,
    /// The access mask, possibly containing generic bits.
    pub mask: u32,
    /// The SID bytes, without any trailing ACE padding.
    pub sid: &'a [u8],
}

/// A validated, borrowed binary ACL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acl<'a> {
    revision: u8,
    ace_count: u16,
    body: &'a [u8],
}

impl<'a> Acl<'a> {
    /// Parse and validate an ACL from the start of `bytes`.
    ///
    /// The header is checked first: revision, both reserved bytes (`Sbz1` and
    /// `Sbz2`) must be zero, and `AclSize` must be at least the header length,
    /// a multiple of four, and no larger than `bytes`. Only the first
    /// `AclSize` bytes belong to the ACL. Bytes after them are never read, so
    /// callers may pass a larger buffer.
    ///
    /// `AceCount` must be able to fit: each ACE is at least eight bytes, so a
    /// count whose minimum size exceeds the body is rejected before any ACE is
    /// walked. Every ACE must lie entirely inside `AclSize`, and its SID must
    /// lie entirely inside its own `AceSize`. Padding after the SID is allowed.
    /// Slack after the last ACE but inside `AclSize` is also allowed, because
    /// Windows permits it; it is ignored.
    ///
    /// Every allowed or denied ACE is fully decoded. Inherit-only ACEs have
    /// their framing and SID checked but are then skipped, since they never
    /// apply here. An accepted ACL therefore never fails during evaluation.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let [
            revision,
            sbz1,
            size_lo,
            size_hi,
            count_lo,
            count_hi,
            sbz2_lo,
            sbz2_hi,
        ] = read_array::<ACL_HEADER_LEN>(bytes, 0)?;
        let acl_size = usize::from(u16::from_le_bytes([size_lo, size_hi]));
        let ace_count = u16::from_le_bytes([count_lo, count_hi]);
        if !matches!(revision, ACL_REVISION | ACL_REVISION_DS)
            || sbz1 != 0
            || [sbz2_lo, sbz2_hi] != [0, 0]
            || acl_size < ACL_HEADER_LEN
            || !acl_size.is_multiple_of(4)
        {
            return Err(Error::InvalidInput);
        }
        let region = bytes.get(..acl_size).ok_or(Error::InvalidInput)?;
        let body = region.get(ACL_HEADER_LEN..).ok_or(Error::InvalidInput)?;

        let min_ace_bytes = usize::from(ace_count)
            .checked_mul(ACE_HEADER_LEN)
            .ok_or(Error::InvalidInput)?;
        if min_ace_bytes > body.len() {
            return Err(Error::InvalidInput);
        }

        let mut walk = Aces {
            rest: body,
            remaining: ace_count,
        };
        for ace in walk.by_ref() {
            ace?;
        }
        // The walk only advances through `body`, so the bytes it consumed
        // cannot run past the end of AclSize. Input cannot trigger this
        // check; it documents and guards that invariant.
        body.len()
            .checked_sub(walk.rest.len())
            .filter(|consumed| *consumed <= body.len())
            .ok_or(Error::InvalidInput)?;
        Ok(Self {
            revision,
            ace_count,
            body,
        })
    }

    /// Return the ACL revision byte.
    pub const fn revision(&self) -> u8 {
        self.revision
    }

    /// Return the number of ACEs declared by the header.
    pub const fn ace_count(&self) -> u16 {
        self.ace_count
    }

    /// Return `AclSize`: the header plus every body byte, including slack.
    pub const fn size(&self) -> usize {
        ACL_HEADER_LEN + self.body.len()
    }

    /// Encode the ACL into the start of `out`, returning the bytes written.
    ///
    /// The reserved header bytes are written as zero, so the output is
    /// byte-identical to the first `AclSize` bytes that were parsed. Fails
    /// with [`Error::OutOfRange`] if `out` is shorter than [`Acl::size`].
    pub fn write(&self, out: &mut [u8]) -> Result<usize> {
        let size = self.size();
        let [size_lo, size_hi] = u16::try_from(size)
            .map_err(|_| Error::OutOfRange)?
            .to_le_bytes();
        let [count_lo, count_hi] = self.ace_count.to_le_bytes();
        let encoded = out.get_mut(..size).ok_or(Error::OutOfRange)?;
        let (header, body) = encoded
            .split_at_mut_checked(ACL_HEADER_LEN)
            .ok_or(Error::OutOfRange)?;
        header.copy_from_slice(&[self.revision, 0, size_lo, size_hi, count_lo, count_hi, 0, 0]);
        body.copy_from_slice(self.body);
        Ok(size)
    }

    /// Iterate over the allowed and denied ACEs in order.
    ///
    /// Inherit-only ACEs are skipped. After a parse error the iterator yields
    /// that error once and then ends, so it never silently drops a later ACE.
    pub fn aces(&self) -> Aces<'a> {
        Aces {
            rest: self.body,
            remaining: self.ace_count,
        }
    }
}

/// Iterator over the ACEs of an [`Acl`].
#[derive(Clone, Debug)]
pub struct Aces<'a> {
    rest: &'a [u8],
    remaining: u16,
}

impl<'a> Iterator for Aces<'a> {
    type Item = Result<Ace<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining > 0 {
            self.remaining -= 1;
            let (raw, tail) = match split_ace(self.rest) {
                Ok(parts) => parts,
                Err(error) => {
                    self.remaining = 0;
                    return Some(Err(error));
                }
            };
            self.rest = tail;
            match decode_ace(raw) {
                Ok(Some(ace)) => return Some(Ok(ace)),
                Ok(None) => continue,
                Err(error) => {
                    self.remaining = 0;
                    return Some(Err(error));
                }
            }
        }
        None
    }
}

/// Split one ACE off the front of `rest`, checking its declared size.
fn split_ace(rest: &[u8]) -> Result<(&[u8], &[u8])> {
    let header = read_array::<4>(rest, 0)?;
    let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
    if size < ACE_HEADER_LEN || !size.is_multiple_of(4) {
        return Err(Error::InvalidInput);
    }
    rest.split_at_checked(size).ok_or(Error::InvalidInput)
}

/// Decode one complete ACE. Returns `None` for inherit-only entries.
///
/// `ace` is exactly `AceSize` bytes, so the SID check bounds the SID by its
/// own ACE. The SID is checked for every ACE, including inherit-only ones.
fn decode_ace(ace: &[u8]) -> Result<Option<Ace<'_>>> {
    let [kind, flags, _, _] = read_array::<4>(ace, 0)?;
    let sid = parse_sid(ace.get(ACE_HEADER_LEN..).ok_or(Error::InvalidInput)?)?;
    if flags & INHERIT_ONLY_ACE != 0 {
        return Ok(None);
    }
    let kind = match kind {
        ACCESS_ALLOWED_ACE_TYPE => AceKind::Allowed,
        ACCESS_DENIED_ACE_TYPE => AceKind::Denied,
        _ => return Err(Error::Unsupported),
    };
    let mask = u32::from_le_bytes(read_array(ace, 4)?);
    Ok(Some(Ace {
        kind,
        flags,
        mask,
        sid,
    }))
}

/// Check the SID framing and return exactly its bytes.
///
/// `bytes` is the ACE body after its eight-byte header. The SID must fit
/// inside it; any bytes after the SID are padding and are not returned.
fn parse_sid(bytes: &[u8]) -> Result<&[u8]> {
    let [revision, count] = read_array::<2>(bytes, 0)?;
    if revision != SID_REVISION || count > SID_MAX_SUBAUTHORITIES {
        return Err(Error::InvalidInput);
    }
    let len = 8 + 4 * usize::from(count);
    bytes.get(..len).ok_or(Error::InvalidInput)
}

fn read_array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    bytes
        .get(at..)
        .and_then(|rest| rest.get(..N))
        .and_then(|window| window.try_into().ok())
        .ok_or(Error::InvalidInput)
}

/// Decide whether the caller may access an object with `desired` rights.
///
/// `None` is a null DACL and grants everything. An empty DACL denies
/// everything. Otherwise ACEs are applied in order: a deny ACE removes the
/// still-undecided bits it names, and an allow ACE grants its bits unless they
/// were already denied. Any SID in `token_sids` may match an ACE. Bits never
/// decided are denied.
///
/// Generic bits in `desired` and in the ACE masks are mapped first. On success
/// the granted mask is returned. With `MAXIMUM_ALLOWED`, the result is the
/// maximal set of granted rights, and the request fails only if that set is
/// empty or a specifically named right is denied. Any other failure returns
/// [`Error::PermissionDenied`].
pub fn access_check(
    acl: Option<&Acl<'_>>,
    token_sids: &[&[u8]],
    desired: u32,
    mapping: &GenericMapping,
) -> Result<u32> {
    let desired = map_generic(desired, mapping);
    let allowed = match acl {
        None => u32::MAX,
        Some(acl) => granted_rights(acl, token_sids, mapping)?,
    };

    let specific = desired & !MAXIMUM_ALLOWED;
    if specific & !allowed != 0 {
        return Err(Error::PermissionDenied);
    }
    if desired & MAXIMUM_ALLOWED == 0 {
        return Ok(specific);
    }
    let maximal = allowed & GRANTABLE_RIGHTS;
    if maximal == 0 {
        return Err(Error::PermissionDenied);
    }
    Ok(maximal | specific)
}

/// Walk the DACL in order and return every right the token is allowed.
fn granted_rights(acl: &Acl<'_>, token_sids: &[&[u8]], mapping: &GenericMapping) -> Result<u32> {
    let mut granted = 0u32;
    let mut denied = 0u32;
    for ace in acl.aces() {
        let ace = ace?;
        if !token_sids.contains(&ace.sid) {
            continue;
        }
        let mask = map_generic(ace.mask, mapping);
        match ace.kind {
            AceKind::Allowed => granted |= mask & !denied,
            AceKind::Denied => denied |= mask & !granted,
        }
    }
    Ok(granted)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE_READ: u32 = 0x1;
    const FILE_WRITE: u32 = 0x2;
    const FILE_EXECUTE: u32 = 0x20;

    const MAPPING: GenericMapping = GenericMapping {
        read: FILE_READ | READ_CONTROL | SYNCHRONIZE,
        write: FILE_WRITE | READ_CONTROL,
        execute: FILE_EXECUTE | READ_CONTROL | SYNCHRONIZE,
        all: FILE_READ | FILE_WRITE | FILE_EXECUTE | DELETE | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE,
    };

    /// S-1-1-0 (Everyone).
    const WORLD: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    /// S-1-5-21-1000.
    const ALICE: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xe8, 3, 0, 0];
    /// S-1-5-21-1001.
    const BOB: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xe9, 3, 0, 0];

    /// One ACE, sized from its SID and padded to four bytes.
    fn ace(kind: u8, flags: u8, mask: u32, sid: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let size = (ACE_HEADER_LEN + sid.len()).next_multiple_of(4);
        out[0] = kind;
        out[1] = flags;
        out[2..4].copy_from_slice(&(size as u16).to_le_bytes());
        out[4..8].copy_from_slice(&mask.to_le_bytes());
        out[8..8 + sid.len()].copy_from_slice(sid);
        out
    }

    /// An ACL holding `aces`; `AclSize` is computed from the ACE sizes.
    fn acl_bytes(revision: u8, aces: &[[u8; 32]]) -> [u8; 256] {
        let mut out = [0u8; 256];
        out[0] = revision;
        let mut at = ACL_HEADER_LEN;
        for ace in aces {
            let len = usize::from(u16::from_le_bytes([ace[2], ace[3]]));
            out[at..at + len].copy_from_slice(&ace[..len]);
            at += len;
        }
        out[2..4].copy_from_slice(&(at as u16).to_le_bytes());
        out[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
        out
    }

    fn dacl(aces: &[[u8; 32]]) -> [u8; 256] {
        acl_bytes(ACL_REVISION, aces)
    }

    #[test]
    fn map_generic_translates_each_generic_bit() {
        assert_eq!(map_generic(GENERIC_READ, &MAPPING), MAPPING.read);
        assert_eq!(
            map_generic(GENERIC_WRITE | GENERIC_EXECUTE, &MAPPING),
            MAPPING.write | MAPPING.execute
        );
        assert_eq!(map_generic(GENERIC_ALL, &MAPPING), MAPPING.all);
        assert_eq!(
            map_generic(DELETE | GENERIC_READ, &MAPPING),
            DELETE | MAPPING.read
        );
        let mapped = map_generic(u32::MAX, &MAPPING);
        assert_eq!(mapped & GENERIC_BITS, 0);
    }

    #[test]
    fn map_generic_leaves_specific_and_maximum_bits_alone() {
        assert_eq!(map_generic(FILE_READ, &MAPPING), FILE_READ);
        assert_eq!(map_generic(MAXIMUM_ALLOWED, &MAPPING), MAXIMUM_ALLOWED);
    }

    #[test]
    fn parse_accepts_empty_dacl() {
        let buf = dacl(&[]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(acl.revision(), ACL_REVISION);
        assert_eq!(acl.ace_count(), 0);
        assert_eq!(acl.aces().count(), 0);
    }

    #[test]
    fn parse_rejects_bad_revision_and_sizes() {
        let mut buf = dacl(&[]);
        buf[0] = 3;
        assert_eq!(Acl::parse(&buf), Err(Error::InvalidInput));

        let mut buf = dacl(&[]);
        buf[2..4].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(Acl::parse(&buf), Err(Error::InvalidInput));

        let mut buf = dacl(&[]);
        buf[2..4].copy_from_slice(&0x100u16.to_le_bytes());
        assert_eq!(Acl::parse(&buf[..16]), Err(Error::InvalidInput));
    }

    #[test]
    fn parse_rejects_bad_ace_sizes() {
        let mut short = ace(0, 0, FILE_READ, &WORLD);
        short[2..4].copy_from_slice(&6u16.to_le_bytes());
        assert_eq!(
            Acl::parse(&dacl(&[short])).map(|_| ()),
            Err(Error::InvalidInput)
        );

        let mut unaligned = ace(0, 0, FILE_READ, &WORLD);
        unaligned[2..4].copy_from_slice(&22u16.to_le_bytes());
        assert_eq!(
            Acl::parse(&dacl(&[unaligned])).map(|_| ()),
            Err(Error::InvalidInput)
        );

        // AclSize cuts the 24-byte ACE short, so it runs past the ACL.
        let mut buf = dacl(&[ace(0, 0, FILE_READ, &ALICE)]);
        buf[2..4].copy_from_slice(&20u16.to_le_bytes());
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));
    }

    #[test]
    fn parse_rejects_truncated_ace_list() {
        let mut buf = dacl(&[ace(0, 0, FILE_READ, &WORLD)]);
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));
    }

    #[test]
    fn parse_rejects_malformed_sids() {
        let bad_revision = [2u8, 0, 0, 0, 0, 0, 0, 1];
        let too_many = [1u8, 16, 0, 0, 0, 0, 0, 5];
        let truncated = [1u8, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0];
        for sid in [&bad_revision[..], &too_many[..], &truncated[..]] {
            let buf = dacl(&[ace(0, 0, FILE_READ, sid)]);
            assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));
        }
    }

    #[test]
    fn parse_rejects_unknown_ace_types_but_skips_inherit_only() {
        let audit = ace(2, 0, FILE_READ, &WORLD);
        assert_eq!(
            Acl::parse(&dacl(&[audit])).map(|_| ()),
            Err(Error::Unsupported)
        );

        let inherited = ace(2, INHERIT_ONLY_ACE, FILE_READ, &WORLD);
        let buf = dacl(&[inherited]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(acl.aces().count(), 0);
    }

    /// The `AclSize` field of a serialized ACL.
    fn acl_size_of(buf: &[u8]) -> usize {
        usize::from(u16::from_le_bytes([buf[2], buf[3]]))
    }

    #[test]
    fn parse_rejects_nonzero_reserved_header_bytes() {
        // Sbz1 is byte 1.
        let mut buf = dacl(&[]);
        buf[1] = 1;
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));

        // Sbz2 is bytes 6 and 7.
        let mut buf = dacl(&[]);
        buf[6] = 1;
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));

        let mut buf = dacl(&[]);
        buf[7] = 0x80;
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));
    }

    #[test]
    fn parse_rejects_truncated_header() {
        let buf = dacl(&[]);
        for len in 0..ACL_HEADER_LEN {
            assert_eq!(
                Acl::parse(&buf[..len]).map(|_| ()),
                Err(Error::InvalidInput)
            );
        }
    }

    #[test]
    fn parse_requires_acl_size_to_be_dword_aligned() {
        let mut buf = dacl(&[]);
        buf[2..4].copy_from_slice(&10u16.to_le_bytes());
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));

        let mut buf = dacl(&[]);
        buf[2..4].copy_from_slice(&12u16.to_le_bytes());
        assert!(Acl::parse(&buf).is_ok());
    }

    #[test]
    fn parse_rejects_acl_size_beyond_input() {
        // One WORLD ACE makes AclSize 28.
        let buf = dacl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &WORLD)]);
        assert_eq!(acl_size_of(&buf), 28);
        assert_eq!(Acl::parse(&buf[..27]).map(|_| ()), Err(Error::InvalidInput));
        assert!(Acl::parse(&buf[..28]).is_ok());
    }

    #[test]
    fn parse_never_reads_past_acl_size() {
        // A valid ACE exists only beyond AclSize, and AceCount claims it.
        // It must not be read, so the ACL is rejected.
        let mut buf = dacl(&[]);
        buf[4..6].copy_from_slice(&1u16.to_le_bytes());
        let beyond = ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &WORLD);
        buf[8..8 + 20].copy_from_slice(&beyond[..20]);
        assert_eq!(acl_size_of(&buf), 8);
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));
    }

    #[test]
    fn parse_ignores_bytes_after_acl_size() {
        let mut buf = dacl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &ALICE)]);
        let size = acl_size_of(&buf);
        // Fill the tail with bytes that would be an invalid ACE if read.
        buf[size..].fill(0xff);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(acl.aces().count(), 1);
        assert_eq!(Acl::parse(&buf[..size]).unwrap(), acl);
    }

    #[test]
    fn parse_allows_slack_inside_acl_size() {
        // Grow AclSize by 8 zero bytes after the last ACE.
        let mut buf = dacl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &WORLD)]);
        buf[2..4].copy_from_slice(&36u16.to_le_bytes());
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(acl.aces().count(), 1);

        let mut buf = dacl(&[]);
        buf[2..4].copy_from_slice(&16u16.to_le_bytes());
        assert_eq!(Acl::parse(&buf).unwrap().aces().count(), 0);
    }

    #[test]
    fn parse_rejects_ace_count_that_cannot_fit() {
        // Three ACEs need at least 24 body bytes, but AclSize leaves 16.
        let mut buf = dacl(&[]);
        buf[2..4].copy_from_slice(&24u16.to_le_bytes());
        buf[4..6].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));

        // The largest count with the smallest AclSize.
        let mut buf = dacl(&[]);
        buf[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));
    }

    #[test]
    fn parse_rejects_sid_that_overruns_its_ace() {
        // The ACE is 16 bytes, but its 12-byte SID needs 20. The SID still
        // lies inside AclSize, so only the per-ACE check catches it.
        let mut buf = [0u8; 32];
        buf[0] = ACL_REVISION;
        buf[2..4].copy_from_slice(&32u16.to_le_bytes());
        buf[4..6].copy_from_slice(&1u16.to_le_bytes());
        buf[8] = ACCESS_ALLOWED_ACE_TYPE;
        buf[10..12].copy_from_slice(&16u16.to_le_bytes());
        buf[12..16].copy_from_slice(&FILE_READ.to_le_bytes());
        buf[16..28].copy_from_slice(&WORLD);
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));
    }

    #[test]
    fn parse_allows_padding_after_sid() {
        // A 12-byte SID in a 24-byte ACE leaves 4 bytes of padding.
        let mut buf = [0u8; 32];
        buf[0] = ACL_REVISION;
        buf[2..4].copy_from_slice(&32u16.to_le_bytes());
        buf[4..6].copy_from_slice(&1u16.to_le_bytes());
        buf[8] = ACCESS_ALLOWED_ACE_TYPE;
        buf[10..12].copy_from_slice(&24u16.to_le_bytes());
        buf[12..16].copy_from_slice(&FILE_READ.to_le_bytes());
        buf[16..28].copy_from_slice(&WORLD);
        let acl = Acl::parse(&buf).unwrap();
        let ace = acl.aces().next().unwrap().unwrap();
        assert_eq!(ace.mask, FILE_READ);
        assert_eq!(ace.sid, &WORLD[..]);
    }

    #[test]
    fn parse_checks_sids_of_inherit_only_aces() {
        let bad_revision = [2u8, 0, 0, 0, 0, 0, 0, 1];
        let buf = dacl(&[ace(
            ACCESS_ALLOWED_ACE_TYPE,
            INHERIT_ONLY_ACE,
            FILE_READ,
            &bad_revision,
        )]);
        assert_eq!(Acl::parse(&buf).map(|_| ()), Err(Error::InvalidInput));
    }

    #[test]
    fn write_reproduces_parsed_bytes() {
        // Include slack inside AclSize so it must be carried through.
        let mut buf = dacl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &ALICE)]);
        buf[2..4].copy_from_slice(&40u16.to_le_bytes());
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(acl.size(), 40);

        let mut out = [0xeeu8; 64];
        assert_eq!(acl.write(&mut out), Ok(40));
        assert_eq!(out[..40], buf[..40]);
        assert_eq!(Acl::parse(&out).unwrap(), acl);

        for len in 0..40 {
            assert_eq!(acl.write(&mut out[..len]), Err(Error::OutOfRange));
        }
    }

    #[test]
    fn valid_acl_embedded_in_larger_buffer() {
        let small = dacl(&[
            ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &ALICE),
            ace(ACCESS_DENIED_ACE_TYPE, 0, FILE_WRITE, &BOB),
        ]);
        let size = acl_size_of(&small);
        // Surround the ACL with bytes that would be invalid if read.
        let mut big = [0xa5u8; 512];
        big[..size].copy_from_slice(&small[..size]);

        let acl = Acl::parse(&big).unwrap();
        assert_eq!(acl.ace_count(), 2);
        assert_eq!(acl.aces().count(), 2);
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_READ, &MAPPING),
            Ok(FILE_READ)
        );
        assert_eq!(
            access_check(Some(&acl), &[&BOB], FILE_WRITE, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn null_dacl_grants_everything() {
        assert_eq!(
            access_check(None, &[], GENERIC_ALL, &MAPPING),
            Ok(MAPPING.all)
        );
        assert_eq!(
            access_check(None, &[], MAXIMUM_ALLOWED, &MAPPING),
            Ok(GRANTABLE_RIGHTS)
        );
    }

    #[test]
    fn empty_dacl_denies_everything() {
        let buf = dacl(&[]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_READ, &MAPPING),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], MAXIMUM_ALLOWED, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn deny_before_allow_denies_shared_bit() {
        let buf = dacl(&[
            ace(ACCESS_DENIED_ACE_TYPE, 0, FILE_READ, &ALICE),
            ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ | FILE_WRITE, &ALICE),
        ]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_READ, &MAPPING),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_WRITE, &MAPPING),
            Ok(FILE_WRITE)
        );
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], MAXIMUM_ALLOWED, &MAPPING),
            Ok(FILE_WRITE)
        );
    }

    #[test]
    fn allow_before_deny_keeps_earlier_grant() {
        let buf = dacl(&[
            ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &ALICE),
            ace(ACCESS_DENIED_ACE_TYPE, 0, FILE_READ | FILE_WRITE, &ALICE),
        ]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_READ, &MAPPING),
            Ok(FILE_READ)
        );
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_WRITE, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn deny_matches_any_token_sid() {
        let buf = dacl(&[
            ace(ACCESS_DENIED_ACE_TYPE, 0, FILE_READ, &BOB),
            ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &ALICE),
        ]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_READ, &MAPPING),
            Ok(FILE_READ)
        );
        assert_eq!(
            access_check(Some(&acl), &[&BOB], FILE_READ, &MAPPING),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            access_check(Some(&acl), &[&ALICE, &BOB], FILE_READ, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn any_token_sid_can_be_granted() {
        let buf = dacl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &BOB)]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&WORLD, &BOB], FILE_READ, &MAPPING),
            Ok(FILE_READ)
        );
    }

    #[test]
    fn undecided_bits_are_denied() {
        let buf = dacl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &ALICE)]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_READ | FILE_WRITE, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn inherit_only_ace_grants_nothing() {
        let buf = dacl(&[ace(
            ACCESS_ALLOWED_ACE_TYPE,
            INHERIT_ONLY_ACE,
            FILE_READ,
            &ALICE,
        )]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_READ, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn generic_request_is_mapped_before_check() {
        let buf = dacl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0, MAPPING.read, &ALICE)]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], GENERIC_READ, &MAPPING),
            Ok(MAPPING.read)
        );
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], GENERIC_WRITE, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn generic_bits_in_ace_masks_are_mapped() {
        let buf = dacl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_WRITE, &ALICE)]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_WRITE, &MAPPING),
            Ok(FILE_WRITE)
        );
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], FILE_READ, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn maximum_allowed_reports_the_granted_set() {
        let buf = dacl(&[
            ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &WORLD),
            ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_WRITE, &ALICE),
        ]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&WORLD, &ALICE], MAXIMUM_ALLOWED, &MAPPING),
            Ok(FILE_READ | FILE_WRITE)
        );
    }

    #[test]
    fn maximum_allowed_fails_without_any_grant() {
        let buf = dacl(&[ace(ACCESS_DENIED_ACE_TYPE, 0, FILE_READ, &ALICE)]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], MAXIMUM_ALLOWED, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn maximum_allowed_still_requires_named_rights() {
        let buf = dacl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ, &ALICE)]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(
                Some(&acl),
                &[&ALICE],
                MAXIMUM_ALLOWED | FILE_WRITE,
                &MAPPING
            ),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], MAXIMUM_ALLOWED | FILE_READ, &MAPPING),
            Ok(FILE_READ)
        );
    }

    #[test]
    fn maximum_allowed_excludes_rights_denied_first() {
        let buf = dacl(&[
            ace(ACCESS_DENIED_ACE_TYPE, 0, FILE_WRITE, &ALICE),
            ace(ACCESS_ALLOWED_ACE_TYPE, 0, FILE_READ | FILE_WRITE, &ALICE),
        ]);
        let acl = Acl::parse(&buf).unwrap();
        assert_eq!(
            access_check(Some(&acl), &[&ALICE], MAXIMUM_ALLOWED, &MAPPING),
            Ok(FILE_READ)
        );
    }
}
