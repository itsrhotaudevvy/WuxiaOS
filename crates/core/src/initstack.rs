//! System V x86_64 initial process stacks.
//!
//! [`build`] writes the image a loader hands to a new process: `argc`, the
//! `argv` and `envp` pointer vectors, and the auxiliary vector. Strings and
//! the `AT_RANDOM` bytes sit above them. The image is written into the top of
//! a caller-provided buffer whose last byte is `stack_top - 1`, and the return
//! value is the `rsp` the first instruction observes. Nothing outside that
//! top region is touched.
//!
//! Layout, from high to low addresses:
//!
//! ```text
//! stack_top
//!   execfn string, envp strings, argv strings (each NUL-terminated)
//!   16 bytes of AT_RANDOM material
//!   padding of 0..=15 bytes that makes rsp 16-byte aligned
//!   auxv pairs, ending with AT_NULL
//!   envp pointers, NULL
//!   argv pointers, NULL
//! rsp -> argc
//! ```

use crate::paging::{PAGE_SIZE, USER_ADDRESS_LIMIT};
use crate::{Error, Result};

/// Most arguments [`build`] accepts.
pub const MAX_ARGS: usize = 256;

/// Most environment strings [`build`] accepts.
pub const MAX_ENVP: usize = 256;

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

const WORD: u64 = 8;
const RANDOM_LEN: u64 = 16;
const STACK_ALIGN: u64 = 16;

/// Auxiliary vector entries, including the terminating `AT_NULL`.
const AUX_PAIRS: usize = 14;

/// Words in the pointer block that do not depend on argc or envc: the argc
/// word, the two NULL terminators and the auxiliary vector.
const FIXED_WORDS: u64 = 3 + 2 * AUX_PAIRS as u64;

/// Auxiliary vector values supplied by the loader.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuxInfo<'a> {
    /// Address of the program headers in memory (`AT_PHDR`).
    pub phdr: u64,
    /// Size of one program header entry (`AT_PHENT`).
    pub phent: u64,
    /// Number of program header entries (`AT_PHNUM`).
    pub phnum: u64,
    /// Load base of the dynamic linker, or 0 for a static image (`AT_BASE`).
    pub base: u64,
    /// Program entry point (`AT_ENTRY`).
    pub entry: u64,
    /// Real user ID (`AT_UID`).
    pub uid: u32,
    /// Effective user ID (`AT_EUID`).
    pub euid: u32,
    /// Real group ID (`AT_GID`).
    pub gid: u32,
    /// Effective group ID (`AT_EGID`).
    pub egid: u32,
    /// Whether the process runs with elevated privileges (`AT_SECURE`).
    pub secure: bool,
    /// Path the program was executed by, copied into the string area and
    /// referenced by `AT_EXECFN`. Must not contain a NUL byte.
    pub execfn: &'a [u8],
}

/// Builds the initial process stack at the top of `buf`.
///
/// `buf` is the top of the user stack: its last byte is `stack_top - 1`, so
/// `buf.len()` must not exceed `stack_top`. Only the region the image needs is
/// written; it is cleared first, so stale bytes never leak into padding or
/// NULL terminators.
///
/// Returns the `rsp` value at process entry, which points at `argc` and is
/// 16-byte aligned.
///
/// # Errors
///
/// - [`Error::BadAddress`] when `stack_top` lies above the user address limit.
/// - [`Error::InvalidInput`] when an argument, environment string or the
///   execfn contains a NUL byte.
/// - [`Error::OutOfRange`] when argv or envp exceeds [`MAX_ARGS`] or
///   [`MAX_ENVP`], when `buf` is longer than `stack_top`, or when the image
///   does not fit in `buf`. Arithmetic overflow is reported the same way.
pub fn build(
    buf: &mut [u8],
    stack_top: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    aux: &AuxInfo<'_>,
    random: [u8; 16],
) -> Result<u64> {
    if argv.len() > MAX_ARGS || envp.len() > MAX_ENVP {
        return Err(Error::OutOfRange);
    }
    if stack_top > USER_ADDRESS_LIMIT {
        return Err(Error::BadAddress);
    }
    if len_u64(buf.len())? > stack_top {
        return Err(Error::OutOfRange);
    }
    validate(argv)?;
    validate(envp)?;
    validate(&[aux.execfn])?;

    // Size of the string area, including the random bytes that sit above the
    // pointer block.
    let mut area = string_size(aux.execfn)?;
    for string in argv.iter().chain(envp.iter()) {
        area = area
            .checked_add(string_size(string)?)
            .ok_or(Error::OutOfRange)?;
    }
    let random_at = stack_top
        .checked_sub(area)
        .and_then(|address| address.checked_sub(RANDOM_LEN))
        .ok_or(Error::OutOfRange)?;

    let argc = len_u64(argv.len())?;
    let envc = len_u64(envp.len())?;
    let words = argc
        .checked_add(envc)
        .and_then(|count| count.checked_add(FIXED_WORDS))
        .ok_or(Error::OutOfRange)?;
    let block = words.checked_mul(WORD).ok_or(Error::OutOfRange)?;

    // Aligning the pointer block down puts any slack in the padding between
    // the auxv and the random bytes.
    let unaligned = random_at.checked_sub(block).ok_or(Error::OutOfRange)?;
    let rsp = unaligned & !(STACK_ALIGN - 1);
    let used = stack_top.checked_sub(rsp).ok_or(Error::OutOfRange)?;
    let used = usize::try_from(used).map_err(|_| Error::OutOfRange)?;
    let start = buf.len().checked_sub(used).ok_or(Error::OutOfRange)?;
    let image = buf.get_mut(start..).ok_or(Error::OutOfRange)?;
    image.fill(0);

    // Strings are placed from the top down: execfn, then envp, then argv.
    let mut cursor = stack_top;
    let execfn_at = reserve(&mut cursor, string_size(aux.execfn)?)?;
    put(image, rsp, execfn_at, aux.execfn)?;

    let argv_table = slot(rsp, 1)?;
    let envp_table = slot(rsp, argc.checked_add(2).ok_or(Error::OutOfRange)?)?;

    put(image, rsp, rsp, &argc.to_le_bytes())?;
    for (index, string) in envp.iter().enumerate() {
        let at = reserve(&mut cursor, string_size(string)?)?;
        put(image, rsp, at, string)?;
        put(
            image,
            rsp,
            slot(envp_table, len_u64(index)?)?,
            &at.to_le_bytes(),
        )?;
    }
    for (index, string) in argv.iter().enumerate() {
        let at = reserve(&mut cursor, string_size(string)?)?;
        put(image, rsp, at, string)?;
        put(
            image,
            rsp,
            slot(argv_table, len_u64(index)?)?,
            &at.to_le_bytes(),
        )?;
    }

    let random_addr = reserve(&mut cursor, RANDOM_LEN)?;
    put(image, rsp, random_addr, &random)?;

    let auxv_at = slot(
        rsp,
        argc.checked_add(envc)
            .and_then(|n| n.checked_add(3))
            .ok_or(Error::OutOfRange)?,
    )?;
    let pairs: [(u64, u64); AUX_PAIRS] = [
        (AT_PHDR, aux.phdr),
        (AT_PHENT, aux.phent),
        (AT_PHNUM, aux.phnum),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, aux.base),
        (AT_ENTRY, aux.entry),
        (AT_UID, u64::from(aux.uid)),
        (AT_EUID, u64::from(aux.euid)),
        (AT_GID, u64::from(aux.gid)),
        (AT_EGID, u64::from(aux.egid)),
        (AT_SECURE, u64::from(aux.secure)),
        (AT_RANDOM, random_addr),
        (AT_EXECFN, execfn_at),
        (AT_NULL, 0),
    ];
    let mut entry = auxv_at;
    for (key, value) in pairs {
        put(image, rsp, entry, &key.to_le_bytes())?;
        put(image, rsp, slot(entry, 1)?, &value.to_le_bytes())?;
        entry = slot(entry, 2)?;
    }

    Ok(rsp)
}

fn len_u64(len: usize) -> Result<u64> {
    u64::try_from(len).map_err(|_| Error::OutOfRange)
}

/// Bytes a string occupies in the image, including its NUL terminator.
fn string_size(string: &[u8]) -> Result<u64> {
    len_u64(string.len())?
        .checked_add(1)
        .ok_or(Error::OutOfRange)
}

fn validate(strings: &[&[u8]]) -> Result<()> {
    for string in strings {
        if string.contains(&0) {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

/// Moves the string cursor down by `bytes` and returns the new start address.
fn reserve(cursor: &mut u64, bytes: u64) -> Result<u64> {
    *cursor = cursor.checked_sub(bytes).ok_or(Error::OutOfRange)?;
    Ok(*cursor)
}

/// Address of the `index`-th word starting at `base`.
fn slot(base: u64, index: u64) -> Result<u64> {
    index
        .checked_mul(WORD)
        .and_then(|bytes| base.checked_add(bytes))
        .ok_or(Error::OutOfRange)
}

/// Copies `bytes` to virtual address `addr` in an image whose first byte is at
/// `origin`. Bytes that are not overwritten keep their cleared value, which
/// supplies the NUL terminators.
fn put(image: &mut [u8], origin: u64, addr: u64, bytes: &[u8]) -> Result<()> {
    let offset = addr.checked_sub(origin).ok_or(Error::OutOfRange)?;
    let start = usize::try_from(offset).map_err(|_| Error::OutOfRange)?;
    let end = start.checked_add(bytes.len()).ok_or(Error::OutOfRange)?;
    image
        .get_mut(start..end)
        .ok_or(Error::OutOfRange)?
        .copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOP: u64 = 0x7fff_ffff_f000;
    const RANDOM: [u8; 16] = *b"0123456789abcdef";
    const ARGS: [&[u8]; 4] = [b"a", b"bb", b"ccc", b"dddddddddddddddddd"];

    fn aux() -> AuxInfo<'static> {
        AuxInfo {
            phdr: 0x40_0040,
            phent: 56,
            phnum: 3,
            base: 0,
            entry: 0x40_1000,
            uid: 1000,
            euid: 1001,
            gid: 100,
            egid: 101,
            secure: true,
            execfn: b"/bin/init",
        }
    }

    /// Virtual address of the first byte of `buf` when its end is `top`.
    fn origin(buf: &[u8], top: u64) -> u64 {
        top - buf.len() as u64
    }

    fn bytes_at(buf: &[u8], top: u64, addr: u64, len: usize) -> &[u8] {
        let at = (addr - origin(buf, top)) as usize;
        &buf[at..at + len]
    }

    fn word(buf: &[u8], top: u64, addr: u64) -> u64 {
        u64::from_le_bytes(bytes_at(buf, top, addr, 8).try_into().unwrap())
    }

    fn c_string(buf: &[u8], top: u64, addr: u64) -> &[u8] {
        let at = (addr - origin(buf, top)) as usize;
        let len = buf[at..].iter().position(|&b| b == 0).unwrap();
        &buf[at..at + len]
    }

    /// Decodes the auxv starting at `addr` up to and including AT_NULL.
    fn auxv(buf: &[u8], top: u64, mut addr: u64) -> ([(u64, u64); 32], usize) {
        let mut out = [(0, 0); 32];
        let mut count = 0;
        loop {
            let key = word(buf, top, addr);
            let value = word(buf, top, addr + 8);
            out[count] = (key, value);
            count += 1;
            if key == AT_NULL {
                return (out, count);
            }
            addr += 16;
        }
    }

    /// Checks that the NULL-terminated pointer vector at `addr` points, in
    /// order, at `expected`, every string lies in the stack, and the vector
    /// ends with a NULL pointer.
    fn check_vector(buf: &[u8], top: u64, rsp: u64, mut addr: u64, expected: &[&[u8]]) {
        for want in expected {
            let pointer = word(buf, top, addr);
            assert!(
                (rsp..top).contains(&pointer),
                "pointer {pointer:#x} is outside the stack"
            );
            assert_eq!(c_string(buf, top, pointer), *want);
            addr += 8;
        }
        assert_eq!(word(buf, top, addr), 0, "vector is not NULL-terminated");
    }

    #[test]
    fn argv_and_envp_pointers_decode_to_their_strings() {
        let mut buf = [0u8; 1024];
        let argv: [&[u8]; 2] = [b"init", b"--verbose"];
        let envp: [&[u8]; 2] = [b"PATH=/bin", b"HOME=/"];
        let rsp = build(&mut buf, TOP, &argv, &envp, &aux(), RANDOM).unwrap();

        assert_eq!(word(&buf, TOP, rsp), 2);
        check_vector(&buf, TOP, rsp, rsp + 8, &argv);
        check_vector(&buf, TOP, rsp, rsp + 8 * 4, &envp);
    }

    #[test]
    fn rsp_is_16_byte_aligned_for_every_shape_and_top() {
        let mut buf = [0u8; 1024];
        for argc in 0..=4 {
            for envc in 0..=4 {
                for top in [TOP, TOP + 1, TOP + 7, TOP + 15] {
                    let rsp =
                        build(&mut buf, top, &ARGS[..argc], &ARGS[..envc], &aux(), RANDOM).unwrap();
                    assert!(
                        rsp.is_multiple_of(16),
                        "argc {argc} envc {envc} top {top:#x}"
                    );
                    assert_eq!(word(&buf, top, rsp), argc as u64);
                    assert!(rsp < top);
                }
            }
        }
    }

    #[test]
    fn auxv_has_every_entry_in_order_and_ends_with_at_null() {
        let mut buf = [0u8; 1024];
        let argv: [&[u8]; 2] = [b"init", b"--verbose"];
        let envp: [&[u8]; 2] = [b"PATH=/bin", b"HOME=/"];
        let rsp = build(&mut buf, TOP, &argv, &envp, &aux(), RANDOM).unwrap();

        let (pairs, count) = auxv(&buf, TOP, rsp + 8 * 7);
        assert_eq!(count, AUX_PAIRS);
        let fixed = [
            (AT_PHDR, 0x40_0040),
            (AT_PHENT, 56),
            (AT_PHNUM, 3),
            (AT_PAGESZ, 4096),
            (AT_BASE, 0),
            (AT_ENTRY, 0x40_1000),
            (AT_UID, 1000),
            (AT_EUID, 1001),
            (AT_GID, 100),
            (AT_EGID, 101),
            (AT_SECURE, 1),
        ];
        assert_eq!(pairs[..11], fixed);
        assert_eq!(pairs[11].0, AT_RANDOM);
        assert_eq!(pairs[12].0, AT_EXECFN);
        assert_eq!(pairs[13], (AT_NULL, 0));
    }

    #[test]
    fn at_random_points_to_the_supplied_sixteen_bytes() {
        let mut buf = [0u8; 1024];
        let argv: [&[u8]; 1] = [b"init"];
        let rsp = build(&mut buf, TOP, &argv, &[], &aux(), RANDOM).unwrap();

        // argc 1 with no envp: argc, argv, two NULLs, then auxv.
        let (pairs, _) = auxv(&buf, TOP, rsp + 8 * 4);
        let random_at = pairs[11].1;
        assert!((rsp..TOP - 16).contains(&random_at));
        assert_eq!(bytes_at(&buf, TOP, random_at, 16), &RANDOM[..]);
    }

    #[test]
    fn at_execfn_points_to_a_nul_terminated_copy() {
        let mut buf = [0u8; 1024];
        let argv: [&[u8]; 1] = [b"init"];
        let rsp = build(&mut buf, TOP, &argv, &[], &aux(), RANDOM).unwrap();

        let (pairs, _) = auxv(&buf, TOP, rsp + 8 * 4);
        let execfn_at = pairs[12].1;
        assert!((rsp..TOP).contains(&execfn_at));
        assert_eq!(c_string(&buf, TOP, execfn_at), &b"/bin/init"[..]);
    }

    #[test]
    fn empty_argv_and_envp_still_terminate_both_vectors() {
        let mut buf = [0u8; 512];
        let rsp = build(&mut buf, TOP, &[], &[], &aux(), RANDOM).unwrap();

        assert!(rsp.is_multiple_of(16));
        assert_eq!(word(&buf, TOP, rsp), 0);
        assert_eq!(word(&buf, TOP, rsp + 8), 0);
        assert_eq!(word(&buf, TOP, rsp + 16), 0);
        let (pairs, count) = auxv(&buf, TOP, rsp + 24);
        assert_eq!(count, AUX_PAIRS);
        assert_eq!(pairs[13], (AT_NULL, 0));
    }

    #[test]
    fn rejects_interior_nul_in_argv_envp_and_execfn() {
        let mut buf = [0u8; 512];
        let bad_argv: [&[u8]; 1] = [b"a\0b"];
        assert_eq!(
            build(&mut buf, TOP, &bad_argv, &[], &aux(), RANDOM),
            Err(Error::InvalidInput)
        );
        let bad_envp: [&[u8]; 1] = [b"X=\0"];
        assert_eq!(
            build(&mut buf, TOP, &[], &bad_envp, &aux(), RANDOM),
            Err(Error::InvalidInput)
        );
        let mut bad_execfn = aux();
        bad_execfn.execfn = &b"/a\0"[..];
        assert_eq!(
            build(&mut buf, TOP, &[], &[], &bad_execfn, RANDOM),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn enforces_the_argc_and_envc_bounds() {
        let mut big = [0u8; 16384];
        let many: [&[u8]; MAX_ARGS + 1] = [&b"x"[..]; MAX_ARGS + 1];

        assert!(build(&mut big, TOP, &many[..MAX_ARGS], &[], &aux(), RANDOM).is_ok());
        assert_eq!(
            build(&mut big, TOP, &many, &[], &aux(), RANDOM),
            Err(Error::OutOfRange)
        );
        assert!(build(&mut big, TOP, &[], &many[..MAX_ENVP], &aux(), RANDOM).is_ok());
        assert_eq!(
            build(&mut big, TOP, &[], &many, &aux(), RANDOM),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn buffer_must_hold_the_whole_image() {
        let argv: [&[u8]; 2] = [b"init", b"--verbose"];
        let envp: [&[u8]; 2] = [b"PATH=/bin", b"HOME=/"];
        let mut big = [0u8; 4096];
        let rsp = build(&mut big, TOP, &argv, &envp, &aux(), RANDOM).unwrap();
        let used = (TOP - rsp) as usize;

        // The image ends at the buffer end, so a tail slice of exactly `used`
        // bytes is the smallest buffer that works.
        let start = big.len() - used;
        assert_eq!(
            build(&mut big[start..], TOP, &argv, &envp, &aux(), RANDOM),
            Ok(rsp)
        );
        assert_eq!(
            build(&mut big[start + 1..], TOP, &argv, &envp, &aux(), RANDOM),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            build(&mut [], TOP, &argv, &envp, &aux(), RANDOM),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn rejects_stack_tops_above_the_user_limit() {
        let mut buf = [0u8; 1024];
        assert_eq!(
            build(&mut buf, USER_ADDRESS_LIMIT + 1, &[], &[], &aux(), RANDOM),
            Err(Error::BadAddress)
        );
        assert!(build(&mut buf, USER_ADDRESS_LIMIT, &[], &[], &aux(), RANDOM).is_ok());
    }

    #[test]
    fn rejects_a_buffer_longer_than_the_stack_top() {
        let mut buf = [0u8; 1024];
        assert_eq!(
            build(&mut buf, 512, &[], &[], &aux(), RANDOM),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn writes_only_the_top_of_the_buffer() {
        let mut buf = [0xAA_u8; 1024];
        let argv: [&[u8]; 2] = [b"init", b"--verbose"];
        let envp: [&[u8]; 1] = [b"HOME=/"];
        let rsp = build(&mut buf, TOP, &argv, &envp, &aux(), RANDOM).unwrap();

        let start = buf.len() - (TOP - rsp) as usize;
        assert!(buf[..start].iter().all(|&b| b == 0xAA));
        // Stale 0xAA bytes inside the image are cleared, so the NULL
        // terminators of both vectors read as zero.
        check_vector(&buf, TOP, rsp, rsp + 8, &argv);
        check_vector(&buf, TOP, rsp, rsp + 8 * 4, &envp);
    }
}
