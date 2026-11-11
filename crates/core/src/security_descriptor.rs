//! Self-relative NT security descriptors.
//!
//! A self-relative `SECURITY_DESCRIPTOR` is a 20-byte header followed by its
//! components, which the header locates by byte offsets from the start of the
//! descriptor:
//!
//! ```text
//! 0  Revision (1)     1  Sbz1 (or RM control)   2  Control (u16)
//! 4  Owner offset     8  Group offset           12 SACL offset   16 DACL offset
//! ```
//!
//! The bytes are untrusted. [`SecurityDescriptor::parse`] accepts only the
//! self-relative form, because the absolute form holds raw pointers that mean
//! nothing outside the address space that built them. Every component must
//! start after the header on a four-byte boundary, lie entirely inside the
//! input, and not overlap any other component. SIDs are decoded with
//! [`Sid::parse_binary`] and ACLs with [`Acl::parse`], so a parsed descriptor
//! holds only validated parts.

use crate::acl::{self, Acl, GenericMapping};
use crate::sid::Sid;
use crate::{Error, Result};

/// The only security descriptor revision.
pub const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
/// Length of the self-relative header.
pub const HEADER_LEN: usize = 20;

/// The owner SID was supplied by a defaulting mechanism.
pub const SE_OWNER_DEFAULTED: u16 = 0x0001;
/// The group SID was supplied by a defaulting mechanism.
pub const SE_GROUP_DEFAULTED: u16 = 0x0002;
/// The descriptor carries a DACL, possibly a NULL one.
pub const SE_DACL_PRESENT: u16 = 0x0004;
/// The DACL was supplied by a defaulting mechanism.
pub const SE_DACL_DEFAULTED: u16 = 0x0008;
/// The descriptor carries a SACL, possibly a NULL one.
pub const SE_SACL_PRESENT: u16 = 0x0010;
/// The SACL was supplied by a defaulting mechanism.
pub const SE_SACL_DEFAULTED: u16 = 0x0020;
/// The DACL was set by an untrusted source (compound ACEs).
pub const SE_DACL_UNTRUSTED: u16 = 0x0040;
/// Server security was requested.
pub const SE_SERVER_SECURITY: u16 = 0x0080;
/// Request automatic DACL inheritance propagation.
pub const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
/// Request automatic SACL inheritance propagation.
pub const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
/// The DACL was set up for automatic inheritance.
pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
/// The SACL was set up for automatic inheritance.
pub const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
/// The DACL does not inherit ACEs from its parent.
pub const SE_DACL_PROTECTED: u16 = 0x1000;
/// The SACL does not inherit ACEs from its parent.
pub const SE_SACL_PROTECTED: u16 = 0x2000;
/// `Sbz1` carries resource-manager control bits.
pub const SE_RM_CONTROL_VALID: u16 = 0x4000;
/// The descriptor is in self-relative form.
pub const SE_SELF_RELATIVE: u16 = 0x8000;

/// Control bits that [`SecurityDescriptor::write`] derives from the other
/// fields instead of copying from [`SecurityDescriptor::control`].
const DERIVED_CONTROL: u16 =
    SE_DACL_PRESENT | SE_SACL_PRESENT | SE_RM_CONTROL_VALID | SE_SELF_RELATIVE;

/// How a descriptor carries one of its ACLs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AclSlot<'a> {
    /// The present flag is clear; the descriptor has no such ACL.
    Absent,
    /// The present flag is set but the offset is zero: a NULL ACL.
    Null,
    /// The present flag is set and the offset locates a validated ACL.
    Present(Acl<'a>),
}

/// What the DACL of a descriptor means for an access check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaclPolicy<'a> {
    /// No DACL, or a NULL DACL: every requested right is granted.
    GrantAll,
    /// A DACL with no ACE that takes part in access checks, such as an empty
    /// DACL or one holding only inherit-only ACEs: every right is denied.
    DenyAll,
    /// A DACL whose ACEs must be evaluated in order.
    Evaluate(Acl<'a>),
}

/// A validated self-relative security descriptor.
///
/// Fields are public so callers can build a descriptor to serialize. A SID or
/// ACL can only exist in validated form, so any value of this type can be
/// written. The presence, self-relative and resource-manager bits of
/// `control` are derived from the other fields when writing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityDescriptor<'a> {
    /// The raw control word. After [`SecurityDescriptor::parse`] it is exactly
    /// the input value.
    pub control: u16,
    /// The `Sbz1` byte when [`SE_RM_CONTROL_VALID`] is set.
    pub rm_control: Option<u8>,
    /// The owner SID, if any.
    pub owner: Option<Sid>,
    /// The primary group SID, if any.
    pub group: Option<Sid>,
    /// The system ACL.
    pub sacl: AclSlot<'a>,
    /// The discretionary ACL.
    pub dacl: AclSlot<'a>,
}

impl<'a> SecurityDescriptor<'a> {
    /// Parse and validate a self-relative descriptor at the start of `bytes`.
    ///
    /// The header must have revision 1 and [`SE_SELF_RELATIVE`] set. `Sbz1`
    /// must be zero unless [`SE_RM_CONTROL_VALID`] is set, in which case it is
    /// returned as [`SecurityDescriptor::rm_control`]. An offset of zero means
    /// the component is missing. A DACL or SACL offset must be zero when its
    /// present flag is clear; with the flag set, offset zero is a NULL ACL.
    ///
    /// Every non-zero offset must be at least [`HEADER_LEN`], a multiple of
    /// four, and locate a component that fits inside `bytes` without
    /// overlapping another component. Bytes not covered by any component are
    /// never read, so callers may pass a larger buffer.
    ///
    /// Malformed framing fails with [`Error::InvalidInput`]. Component errors
    /// are passed through: a SID with too many sub-authorities is
    /// [`Error::OutOfRange`], and an ACL holding ACE types the ACL model does
    /// not decode (for example audit ACEs in a SACL) is
    /// [`Error::Unsupported`].
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let header = bytes
            .first_chunk::<HEADER_LEN>()
            .ok_or(Error::InvalidInput)?;
        let [revision, sbz1, control_lo, control_hi] = word(header, 0)?;
        let control = u16::from_le_bytes([control_lo, control_hi]);
        if revision != SECURITY_DESCRIPTOR_REVISION || control & SE_SELF_RELATIVE == 0 {
            return Err(Error::InvalidInput);
        }
        let rm_control = if control & SE_RM_CONTROL_VALID != 0 {
            Some(sbz1)
        } else if sbz1 != 0 {
            return Err(Error::InvalidInput);
        } else {
            None
        };

        let owner_offset = u32::from_le_bytes(word(header, 4)?);
        let group_offset = u32::from_le_bytes(word(header, 8)?);
        let sacl_offset = u32::from_le_bytes(word(header, 12)?);
        let dacl_offset = u32::from_le_bytes(word(header, 16)?);

        let mut extents = Extents::new();
        let owner = parse_sid_at(bytes, owner_offset, &mut extents)?;
        let group = parse_sid_at(bytes, group_offset, &mut extents)?;
        let sacl = parse_acl_at(
            bytes,
            control & SE_SACL_PRESENT != 0,
            sacl_offset,
            &mut extents,
        )?;
        let dacl = parse_acl_at(
            bytes,
            control & SE_DACL_PRESENT != 0,
            dacl_offset,
            &mut extents,
        )?;

        Ok(Self {
            control,
            rm_control,
            owner,
            group,
            sacl,
            dacl,
        })
    }

    /// The control word [`SecurityDescriptor::write`] emits.
    ///
    /// [`SE_SELF_RELATIVE`] is always set. The DACL and SACL present flags and
    /// [`SE_RM_CONTROL_VALID`] follow the corresponding fields. Every other
    /// bit is copied from [`SecurityDescriptor::control`].
    pub fn normalized_control(&self) -> u16 {
        let mut control = (self.control & !DERIVED_CONTROL) | SE_SELF_RELATIVE;
        if self.dacl != AclSlot::Absent {
            control |= SE_DACL_PRESENT;
        }
        if self.sacl != AclSlot::Absent {
            control |= SE_SACL_PRESENT;
        }
        if self.rm_control.is_some() {
            control |= SE_RM_CONTROL_VALID;
        }
        control
    }

    /// Whether [`SE_DACL_PROTECTED`] is set.
    pub const fn dacl_protected(&self) -> bool {
        self.control & SE_DACL_PROTECTED != 0
    }

    /// Whether [`SE_SACL_PROTECTED`] is set.
    pub const fn sacl_protected(&self) -> bool {
        self.control & SE_SACL_PROTECTED != 0
    }

    /// Number of bytes [`SecurityDescriptor::write`] produces.
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN
            + self.owner.map_or(0, |sid| sid.binary_len())
            + self.group.map_or(0, |sid| sid.binary_len())
            + slot_len(&self.sacl)
            + slot_len(&self.dacl)
    }

    /// Serialize into the start of `out` in self-relative form.
    ///
    /// Components are laid out after the header in the order SACL, DACL,
    /// owner, group, each on a four-byte boundary with no gaps. The result
    /// parses back to a descriptor equal to `self` except that `control` is
    /// replaced by [`SecurityDescriptor::normalized_control`]. Fails with
    /// [`Error::OutOfRange`] if `out` is shorter than
    /// [`SecurityDescriptor::encoded_len`]; `out` may then be partly written.
    pub fn write(&self, out: &mut [u8]) -> Result<usize> {
        let total = self.encoded_len();
        let encoded = out.get_mut(..total).ok_or(Error::OutOfRange)?;
        encoded.fill(0);

        let mut at = HEADER_LEN;
        let sacl_offset = write_slot(&self.sacl, encoded, &mut at)?;
        let dacl_offset = write_slot(&self.dacl, encoded, &mut at)?;
        let owner_offset = write_sid(self.owner.as_ref(), encoded, &mut at)?;
        let group_offset = write_sid(self.group.as_ref(), encoded, &mut at)?;
        if at != total {
            return Err(Error::InvalidState);
        }

        let [control_lo, control_hi] = self.normalized_control().to_le_bytes();
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(&[
            SECURITY_DESCRIPTOR_REVISION,
            self.rm_control.unwrap_or(0),
            control_lo,
            control_hi,
        ]);
        for (slot, offset) in header[4..].as_chunks_mut::<4>().0.iter_mut().zip([
            owner_offset,
            group_offset,
            sacl_offset,
            dacl_offset,
        ]) {
            slot.copy_from_slice(&offset.to_le_bytes());
        }
        encoded
            .get_mut(..HEADER_LEN)
            .ok_or(Error::OutOfRange)?
            .copy_from_slice(&header);
        Ok(total)
    }

    /// Classify the DACL for an access check.
    ///
    /// A missing DACL ([`SE_DACL_PRESENT`] clear) and a NULL DACL both grant
    /// everything. A present DACL with no ACE that applies to access checks
    /// denies everything. Any other DACL must be evaluated.
    pub fn dacl_policy(&self) -> DaclPolicy<'a> {
        match self.dacl {
            AclSlot::Absent | AclSlot::Null => DaclPolicy::GrantAll,
            AclSlot::Present(acl) if acl.aces().next().is_none() => DaclPolicy::DenyAll,
            AclSlot::Present(acl) => DaclPolicy::Evaluate(acl),
        }
    }

    /// Run [`acl::access_check`] against this descriptor's DACL.
    ///
    /// A missing or NULL DACL is passed as no DACL, so it grants everything;
    /// an empty DACL is passed as an ACL, so it denies everything.
    pub fn access_check(
        &self,
        token_sids: &[&[u8]],
        desired: u32,
        mapping: &GenericMapping,
    ) -> Result<u32> {
        match self.dacl {
            AclSlot::Absent | AclSlot::Null => {
                acl::access_check(None, token_sids, desired, mapping)
            }
            AclSlot::Present(ref acl) => acl::access_check(Some(acl), token_sids, desired, mapping),
        }
    }
}

/// Byte ranges already claimed by components, used to reject overlaps.
struct Extents {
    ranges: [(usize, usize); 4],
    len: usize,
}

impl Extents {
    const fn new() -> Self {
        Self {
            ranges: [(0, 0); 4],
            len: 0,
        }
    }

    /// Record `start..end`, failing if it overlaps a recorded range.
    fn claim(&mut self, start: usize, end: usize) -> Result<()> {
        let claimed = self.ranges.get(..self.len).ok_or(Error::InvalidState)?;
        if claimed
            .iter()
            .any(|&(other_start, other_end)| start < other_end && other_start < end)
        {
            return Err(Error::InvalidInput);
        }
        let slot = self.ranges.get_mut(self.len).ok_or(Error::InvalidState)?;
        *slot = (start, end);
        self.len += 1;
        Ok(())
    }
}

/// Validate a non-zero component offset and return the bytes from it on.
fn component_at(bytes: &[u8], offset: u32) -> Result<(usize, &[u8])> {
    let start = usize::try_from(offset).map_err(|_| Error::InvalidInput)?;
    if start < HEADER_LEN || !start.is_multiple_of(4) {
        return Err(Error::InvalidInput);
    }
    let rest = bytes.get(start..).ok_or(Error::InvalidInput)?;
    Ok((start, rest))
}

fn parse_sid_at(bytes: &[u8], offset: u32, extents: &mut Extents) -> Result<Option<Sid>> {
    if offset == 0 {
        return Ok(None);
    }
    let (start, rest) = component_at(bytes, offset)?;
    let (sid, len) = Sid::parse_binary(rest)?;
    extents.claim(start, start.checked_add(len).ok_or(Error::InvalidInput)?)?;
    Ok(Some(sid))
}

fn parse_acl_at<'a>(
    bytes: &'a [u8],
    present: bool,
    offset: u32,
    extents: &mut Extents,
) -> Result<AclSlot<'a>> {
    match (present, offset) {
        (false, 0) => Ok(AclSlot::Absent),
        (false, _) => Err(Error::InvalidInput),
        (true, 0) => Ok(AclSlot::Null),
        (true, offset) => {
            let (start, rest) = component_at(bytes, offset)?;
            let acl = Acl::parse(rest)?;
            extents.claim(
                start,
                start.checked_add(acl.size()).ok_or(Error::InvalidInput)?,
            )?;
            Ok(AclSlot::Present(acl))
        }
    }
}

fn slot_len(slot: &AclSlot<'_>) -> usize {
    match slot {
        AclSlot::Present(acl) => acl.size(),
        AclSlot::Absent | AclSlot::Null => 0,
    }
}

/// Write an ACL at `*at`, advance `*at`, and return its offset (or zero).
fn write_slot(slot: &AclSlot<'_>, out: &mut [u8], at: &mut usize) -> Result<u32> {
    let AclSlot::Present(acl) = slot else {
        return Ok(0);
    };
    let offset = u32::try_from(*at).map_err(|_| Error::OutOfRange)?;
    let written = acl.write(out.get_mut(*at..).ok_or(Error::OutOfRange)?)?;
    *at = at.checked_add(written).ok_or(Error::OutOfRange)?;
    Ok(offset)
}

/// Write a SID at `*at`, advance `*at`, and return its offset (or zero).
fn write_sid(sid: Option<&Sid>, out: &mut [u8], at: &mut usize) -> Result<u32> {
    let Some(sid) = sid else {
        return Ok(0);
    };
    let offset = u32::try_from(*at).map_err(|_| Error::OutOfRange)?;
    let written = sid.write_binary(out.get_mut(*at..).ok_or(Error::OutOfRange)?)?;
    *at = at.checked_add(written).ok_or(Error::OutOfRange)?;
    Ok(offset)
}

fn word(bytes: &[u8], at: usize) -> Result<[u8; 4]> {
    bytes
        .get(at..)
        .and_then(|rest| rest.first_chunk::<4>())
        .copied()
        .ok_or(Error::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACL_REVISION, GENERIC_ALL,
        INHERIT_ONLY_ACE, MAXIMUM_ALLOWED, READ_CONTROL,
    };
    use crate::sid;

    const FILE_READ: u32 = 0x1;
    const FILE_WRITE: u32 = 0x2;
    const MAPPING: GenericMapping = GenericMapping {
        read: FILE_READ | READ_CONTROL,
        write: FILE_WRITE | READ_CONTROL,
        execute: READ_CONTROL,
        all: FILE_READ | FILE_WRITE | READ_CONTROL,
    };

    /// S-1-1-0.
    const WORLD: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    /// S-1-5-32-544.
    const ADMINS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
    /// S-1-5-18.
    const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

    /// Write an ACL with one ACE for `sid` into `out`: header (8) + ACE
    /// header (8) + SID. Returns the ACL length.
    fn one_ace_acl(kind: u8, flags: u8, mask: u32, sid: &[u8], out: &mut [u8]) -> usize {
        let ace_len = 8 + sid.len();
        let acl_len = 8 + ace_len;
        out[..acl_len].fill(0);
        out[0] = ACL_REVISION;
        out[2..4].copy_from_slice(&(acl_len as u16).to_le_bytes());
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        out[8] = kind;
        out[9] = flags;
        out[10..12].copy_from_slice(&(ace_len as u16).to_le_bytes());
        out[12..16].copy_from_slice(&mask.to_le_bytes());
        out[16..acl_len].copy_from_slice(sid);
        acl_len
    }

    const EMPTY_ACL: [u8; 8] = [ACL_REVISION, 0, 8, 0, 0, 0, 0, 0];

    fn put_u32(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn header(buf: &mut [u8], control: u16, owner: u32, group: u32, sacl: u32, dacl: u32) {
        buf[0] = SECURITY_DESCRIPTOR_REVISION;
        buf[1] = 0;
        buf[2..4].copy_from_slice(&control.to_le_bytes());
        put_u32(buf, 4, owner);
        put_u32(buf, 8, group);
        put_u32(buf, 12, sacl);
        put_u32(buf, 16, dacl);
    }

    /// `O:BAG:SYD:(A;;FR;;;WD)` laid out owner, group, DACL: 76 bytes.
    fn windows_style() -> [u8; 76] {
        let mut buf = [0u8; 76];
        header(&mut buf, SE_SELF_RELATIVE | SE_DACL_PRESENT, 20, 36, 0, 48);
        buf[20..36].copy_from_slice(&ADMINS);
        buf[36..48].copy_from_slice(&SYSTEM);
        assert_eq!(
            one_ace_acl(
                ACCESS_ALLOWED_ACE_TYPE,
                0,
                FILE_READ,
                &WORLD,
                &mut buf[48..76]
            ),
            28
        );
        buf
    }

    /// A descriptor with every component, in the canonical write order.
    fn full_canonical() -> [u8; 112] {
        let mut buf = [0u8; 112];
        let control = SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT | SE_DACL_PROTECTED;
        // SACL 20..28, DACL 28..56, owner 56..72, group 72..84, 28 spare.
        header(&mut buf, control, 56, 72, 20, 28);
        buf[20..28].copy_from_slice(&EMPTY_ACL);
        assert_eq!(
            one_ace_acl(
                ACCESS_DENIED_ACE_TYPE,
                0,
                FILE_WRITE,
                &WORLD,
                &mut buf[28..56]
            ),
            28
        );
        buf[56..72].copy_from_slice(&ADMINS);
        buf[72..84].copy_from_slice(&SYSTEM);
        buf
    }
    const FULL_LEN: usize = 84;

    #[test]
    fn parses_windows_style_layout() {
        let buf = windows_style();
        let sd = SecurityDescriptor::parse(&buf).unwrap();
        assert_eq!(sd.control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        assert_eq!(sd.rm_control, None);
        assert_eq!(sd.owner, Some(sid::BUILTIN_ADMINISTRATORS));
        assert_eq!(sd.group, Some(sid::LOCAL_SYSTEM));
        assert_eq!(sd.sacl, AclSlot::Absent);
        let AclSlot::Present(dacl) = sd.dacl else {
            panic!("DACL should be present");
        };
        assert_eq!(dacl.ace_count(), 1);
        assert!(!sd.dacl_protected());
        assert_eq!(sd.dacl_policy(), DaclPolicy::Evaluate(dacl));
        assert_eq!(
            sd.access_check(&[&WORLD], FILE_READ, &MAPPING),
            Ok(FILE_READ)
        );
        assert_eq!(
            sd.access_check(&[&WORLD], FILE_WRITE, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn reordered_layout_round_trips_through_canonical_form() {
        let buf = windows_style();
        let sd = SecurityDescriptor::parse(&buf).unwrap();
        let mut out = [0u8; 128];
        let len = sd.write(&mut out).unwrap();
        assert_eq!(len, buf.len());
        assert_eq!(len, sd.encoded_len());
        // The DACL now comes first, then owner and group.
        assert_eq!(u32::from_le_bytes(out[16..20].try_into().unwrap()), 20);
        assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()), 48);
        assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 64);
        assert_eq!(SecurityDescriptor::parse(&out[..len]).unwrap(), sd);
    }

    #[test]
    fn canonical_bytes_round_trip_exactly() {
        let buf = full_canonical();
        let sd = SecurityDescriptor::parse(&buf).unwrap();
        assert!(sd.dacl_protected());
        assert!(!sd.sacl_protected());
        assert_eq!(sd.encoded_len(), FULL_LEN);
        let mut out = [0xccu8; 128];
        assert_eq!(sd.write(&mut out), Ok(FULL_LEN));
        assert_eq!(out[..FULL_LEN], buf[..FULL_LEN]);
        assert_eq!(
            out[FULL_LEN], 0xcc,
            "write must not touch bytes past its length"
        );
    }

    #[test]
    fn built_descriptor_round_trips() {
        let mut acl_bytes = [0u8; 32];
        let acl_len = one_ace_acl(
            ACCESS_ALLOWED_ACE_TYPE,
            0,
            GENERIC_ALL,
            &ADMINS,
            &mut acl_bytes,
        );
        let acl = Acl::parse(&acl_bytes[..acl_len]).unwrap();
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED,
            rm_control: Some(0x5a),
            owner: Some(sid::LOCAL_SYSTEM),
            group: None,
            sacl: AclSlot::Null,
            dacl: AclSlot::Present(acl),
        };
        let mut out = [0u8; 96];
        let len = sd.write(&mut out).unwrap();
        let back = SecurityDescriptor::parse(&out[..len]).unwrap();
        assert_eq!(back.control, sd.normalized_control());
        assert_eq!(back.control & SE_SACL_PRESENT, SE_SACL_PRESENT);
        assert_eq!(back.control & SE_RM_CONTROL_VALID, SE_RM_CONTROL_VALID);
        assert_eq!(back.rm_control, Some(0x5a));
        assert_eq!(
            SecurityDescriptor {
                control: sd.normalized_control(),
                ..sd
            },
            back
        );
    }

    #[test]
    fn write_normalizes_inconsistent_control_bits() {
        let sd = SecurityDescriptor {
            // Claims a DACL, SACL and RM control, but has none, and omits
            // the self-relative bit.
            control: SE_DACL_PRESENT | SE_SACL_PRESENT | SE_RM_CONTROL_VALID | SE_OWNER_DEFAULTED,
            rm_control: None,
            owner: None,
            group: None,
            sacl: AclSlot::Absent,
            dacl: AclSlot::Absent,
        };
        assert_eq!(
            sd.normalized_control(),
            SE_SELF_RELATIVE | SE_OWNER_DEFAULTED
        );
        let mut out = [0u8; HEADER_LEN];
        assert_eq!(sd.write(&mut out), Ok(HEADER_LEN));
        let back = SecurityDescriptor::parse(&out).unwrap();
        assert_eq!(back.control, SE_SELF_RELATIVE | SE_OWNER_DEFAULTED);
    }

    #[test]
    fn write_rejects_short_buffers() {
        let buf = full_canonical();
        let sd = SecurityDescriptor::parse(&buf).unwrap();
        let mut out = [0u8; FULL_LEN];
        for len in 0..FULL_LEN {
            assert_eq!(sd.write(&mut out[..len]), Err(Error::OutOfRange));
        }
        assert_eq!(sd.write(&mut out), Ok(FULL_LEN));
    }

    #[test]
    fn header_only_descriptor_has_no_dacl() {
        let mut buf = [0u8; HEADER_LEN];
        header(&mut buf, SE_SELF_RELATIVE, 0, 0, 0, 0);
        let sd = SecurityDescriptor::parse(&buf).unwrap();
        assert_eq!(sd.owner, None);
        assert_eq!(sd.group, None);
        assert_eq!(sd.dacl, AclSlot::Absent);
        assert_eq!(sd.dacl_policy(), DaclPolicy::GrantAll);
        assert_eq!(sd.access_check(&[], FILE_WRITE, &MAPPING), Ok(FILE_WRITE));
    }

    #[test]
    fn null_dacl_grants_and_empty_dacl_denies() {
        let mut buf = [0u8; 28];
        header(&mut buf, SE_SELF_RELATIVE | SE_DACL_PRESENT, 0, 0, 0, 0);
        let null = SecurityDescriptor::parse(&buf).unwrap();
        assert_eq!(null.dacl, AclSlot::Null);
        assert_eq!(null.dacl_policy(), DaclPolicy::GrantAll);
        assert_eq!(
            null.access_check(&[&WORLD], FILE_READ | FILE_WRITE, &MAPPING),
            Ok(FILE_READ | FILE_WRITE)
        );

        put_u32(&mut buf, 16, 20);
        buf[20..28].copy_from_slice(&EMPTY_ACL);
        let empty = SecurityDescriptor::parse(&buf).unwrap();
        assert!(matches!(empty.dacl, AclSlot::Present(acl) if acl.ace_count() == 0));
        assert_eq!(empty.dacl_policy(), DaclPolicy::DenyAll);
        assert_eq!(
            empty.access_check(&[&WORLD], FILE_READ, &MAPPING),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            empty.access_check(&[&WORLD], MAXIMUM_ALLOWED, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn inherit_only_dacl_denies_everything() {
        let mut buf = [0u8; 48];
        header(&mut buf, SE_SELF_RELATIVE | SE_DACL_PRESENT, 0, 0, 0, 20);
        assert_eq!(
            one_ace_acl(
                ACCESS_ALLOWED_ACE_TYPE,
                INHERIT_ONLY_ACE,
                FILE_READ,
                &WORLD,
                &mut buf[20..48],
            ),
            28
        );
        let sd = SecurityDescriptor::parse(&buf).unwrap();
        assert_eq!(sd.dacl_policy(), DaclPolicy::DenyAll);
        assert_eq!(
            sd.access_check(&[&WORLD], FILE_READ, &MAPPING),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn rejects_absolute_form() {
        let mut buf = windows_style();
        buf[2..4].copy_from_slice(&SE_DACL_PRESENT.to_le_bytes());
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));
    }

    #[test]
    fn rejects_bad_revision() {
        for revision in [0u8, 2, 0xff] {
            let mut buf = windows_style();
            buf[0] = revision;
            assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));
        }
    }

    #[test]
    fn sbz1_must_be_zero_unless_rm_control_is_valid() {
        let mut buf = windows_style();
        buf[1] = 1;
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));

        let control = SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_RM_CONTROL_VALID;
        buf[2..4].copy_from_slice(&control.to_le_bytes());
        let sd = SecurityDescriptor::parse(&buf).unwrap();
        assert_eq!(sd.rm_control, Some(1));

        buf[1] = 0;
        assert_eq!(SecurityDescriptor::parse(&buf).unwrap().rm_control, Some(0));
    }

    #[test]
    fn rejects_offsets_inside_header() {
        for offset in 1..HEADER_LEN as u32 {
            for field in [4, 8, 16] {
                let mut buf = windows_style();
                put_u32(&mut buf, field, offset);
                assert_eq!(
                    SecurityDescriptor::parse(&buf),
                    Err(Error::InvalidInput),
                    "field {field} offset {offset}"
                );
            }
        }
    }

    #[test]
    fn rejects_misaligned_offsets() {
        // Copy the owner one byte later so only alignment is wrong.
        let mut buf = [0u8; 96];
        buf[..76].copy_from_slice(&windows_style());
        buf[77..93].copy_from_slice(&ADMINS);
        put_u32(&mut buf, 4, 77);
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));
        put_u32(&mut buf, 4, 76);
        buf[76..92].copy_from_slice(&ADMINS);
        assert!(SecurityDescriptor::parse(&buf).is_ok());

        for field in [8, 16] {
            let mut buf = windows_style();
            let offset = u32::from_le_bytes(buf[field..field + 4].try_into().unwrap());
            put_u32(&mut buf, field, offset + 2);
            assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));
        }
    }

    #[test]
    fn rejects_out_of_bounds_offsets() {
        for offset in [76u32, 80, 0x1000, u32::MAX - 3, u32::MAX] {
            for field in [4, 8, 16] {
                let mut buf = windows_style();
                put_u32(&mut buf, field, offset);
                assert!(SecurityDescriptor::parse(&buf).is_err());
            }
        }
        // The group starts in bounds but its sub-authorities do not fit.
        let mut buf = windows_style();
        put_u32(&mut buf, 8, 72);
        buf[72..76].copy_from_slice(&[1, 1, 0, 0]);
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));
    }

    #[test]
    fn rejects_overlapping_components() {
        // Owner and group share bytes.
        let mut buf = windows_style();
        put_u32(&mut buf, 8, 20);
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));

        // The group starts inside the owner, at a valid-looking SID.
        let mut buf = windows_style();
        buf[28..40].copy_from_slice(&SYSTEM);
        put_u32(&mut buf, 8, 28);
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));

        // SACL and DACL are the same bytes.
        let mut buf = windows_style();
        let control = SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT;
        buf[2..4].copy_from_slice(&control.to_le_bytes());
        put_u32(&mut buf, 12, 48);
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));

        // The owner sits inside the DACL's ACE.
        let mut buf = windows_style();
        put_u32(&mut buf, 4, 64);
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));
    }

    #[test]
    fn adjacent_components_are_not_overlapping() {
        // Every component of the canonical layout ends where the next starts.
        assert!(SecurityDescriptor::parse(&full_canonical()).is_ok());
    }

    #[test]
    fn acl_offset_requires_present_flag() {
        let mut buf = windows_style();
        buf[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));

        let mut buf = full_canonical();
        let control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
        buf[2..4].copy_from_slice(&control.to_le_bytes());
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));
    }

    #[test]
    fn sacl_slots() {
        let mut buf = full_canonical();
        let sd = SecurityDescriptor::parse(&buf).unwrap();
        assert!(matches!(sd.sacl, AclSlot::Present(acl) if acl.ace_count() == 0));

        put_u32(&mut buf, 12, 0);
        assert_eq!(SecurityDescriptor::parse(&buf).unwrap().sacl, AclSlot::Null);

        // Audit ACEs are not modeled by the ACL parser yet.
        let mut buf = [0u8; 48];
        header(&mut buf, SE_SELF_RELATIVE | SE_SACL_PRESENT, 0, 0, 20, 0);
        assert_eq!(one_ace_acl(2, 0, FILE_READ, &WORLD, &mut buf[20..48]), 28);
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::Unsupported));
    }

    #[test]
    fn component_errors_propagate() {
        let mut buf = windows_style();
        buf[20] = 2; // owner SID revision
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));

        let mut buf = windows_style();
        buf[21] = 16; // owner sub-authority count
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::OutOfRange));

        let mut buf = windows_style();
        buf[48] = 9; // DACL revision
        assert_eq!(SecurityDescriptor::parse(&buf), Err(Error::InvalidInput));
    }

    #[test]
    fn ignores_bytes_after_components() {
        let mut buf = [0xa5u8; 200];
        buf[..76].copy_from_slice(&windows_style());
        assert_eq!(
            SecurityDescriptor::parse(&buf).unwrap(),
            SecurityDescriptor::parse(&windows_style()).unwrap()
        );
    }

    #[test]
    fn every_truncation_is_rejected() {
        let windows = windows_style();
        let full = full_canonical();
        for bytes in [&windows[..], &full[..FULL_LEN]] {
            assert!(SecurityDescriptor::parse(bytes).is_ok());
            for len in 0..bytes.len() {
                assert!(
                    SecurityDescriptor::parse(&bytes[..len]).is_err(),
                    "accepted truncation to {len}"
                );
            }
        }
    }

    /// Parse `bytes`; if accepted, the canonical form must parse back equal.
    fn check_consistent(bytes: &[u8]) {
        let Ok(sd) = SecurityDescriptor::parse(bytes) else {
            return;
        };
        let mut out = [0u8; 512];
        let len = sd
            .write(&mut out)
            .expect("accepted descriptor must serialize");
        assert_eq!(len, sd.encoded_len());
        let back = SecurityDescriptor::parse(&out[..len]).expect("canonical form must parse");
        assert_eq!(
            back,
            SecurityDescriptor {
                control: sd.normalized_control(),
                ..sd
            }
        );
        let mut again = [0u8; 512];
        assert_eq!(back.write(&mut again), Ok(len));
        assert_eq!(out[..len], again[..len]);
    }

    #[test]
    fn single_byte_mutations_never_panic_and_stay_consistent() {
        let windows = windows_style();
        let full = full_canonical();
        for original in [&windows[..], &full[..]] {
            let mut buf = [0u8; 112];
            for at in 0..original.len() {
                for value in [0x00u8, 0x01, 0x02, 0x04, 0x10, 0x14, 0x7f, 0x80, 0xfe, 0xff] {
                    buf[..original.len()].copy_from_slice(original);
                    buf[at] = value;
                    check_consistent(&buf[..original.len()]);
                    buf[at] = original[at] ^ value;
                    check_consistent(&buf[..original.len()]);
                }
            }
        }
    }

    #[test]
    fn offset_sweeps_never_panic() {
        let full = full_canonical();
        for field in [4usize, 8, 12, 16] {
            for offset in (0u32..=128).chain([0x7fff_fffc, 0xffff_fff0, u32::MAX]) {
                let mut buf = full;
                put_u32(&mut buf, field, offset);
                check_consistent(&buf);
            }
        }
        // Every control word, with all offsets in place.
        for control in 0..=u16::MAX {
            let mut buf = full;
            buf[2..4].copy_from_slice(&control.to_le_bytes());
            check_consistent(&buf);
        }
    }
}
