//! ChaCha20 keystream generation (RFC 8439) with fast key erasure, and ASLR
//! base selection.
//!
//! The generator follows the OpenBSD `arc4random` design. After every
//! [`REKEY_BLOCKS`] keystream blocks the key is replaced by bytes drawn from
//! the keystream, and the old key is wiped. A later compromise of the state
//! therefore cannot reveal output produced under earlier keys.
//!
//! Wiping uses ordinary stores followed by [`core::hint::black_box`], which
//! discourages the optimizer from removing them. It does not guarantee that
//! the compiler left no copies of a key in spilled registers or stack slots, so
//! erasure is best effort.

use crate::paging::{PAGE_SIZE, USER_ADDRESS_LIMIT};
use crate::{Error, Result};

/// Bytes in one ChaCha20 keystream block.
pub const BLOCK_SIZE: usize = 64;
/// Bytes in a ChaCha20 key.
pub const KEY_SIZE: usize = 32;
/// Bytes in an RFC 8439 nonce.
pub const NONCE_SIZE: usize = 12;
/// Keystream blocks generated under one key before it is replaced.
///
/// The block that closes an epoch supplies the next key from its first 32
/// bytes and its last 32 bytes are returned as output, so each key protects
/// at most 16 KiB of ordinary output plus that trailing half-block.
pub const REKEY_BLOCKS: u32 = 256;

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
const ZERO_NONCE: [u8; NONCE_SIZE] = [0; NONCE_SIZE];

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn wipe_bytes(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(bytes);
}

fn wipe_words(words: &mut [u32]) {
    words.fill(0);
    core::hint::black_box(words);
}

/// Compute one 64-byte ChaCha20 keystream block as specified by RFC 8439 2.3.
///
/// The block is returned serialized in little-endian order. The counter and
/// nonce follow the RFC layout: the counter is word 12 and the nonce words are
/// 13 to 15.
pub fn chacha20_block(
    key: &[u8; KEY_SIZE],
    counter: u32,
    nonce: &[u8; NONCE_SIZE],
) -> [u8; BLOCK_SIZE] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&SIGMA);
    let (key_words, _) = key.as_chunks::<4>();
    for (word, bytes) in state[4..12].iter_mut().zip(key_words) {
        *word = u32::from_le_bytes(*bytes);
    }
    state[12] = counter;
    let (nonce_words, _) = nonce.as_chunks::<4>();
    for (word, bytes) in state[13..16].iter_mut().zip(nonce_words) {
        *word = u32::from_le_bytes(*bytes);
    }

    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut output = [0u8; BLOCK_SIZE];
    let (out_words, _) = output.as_chunks_mut::<4>();
    for ((bytes, work), init) in out_words.iter_mut().zip(working).zip(state) {
        *bytes = work.wrapping_add(init).to_le_bytes();
    }
    wipe_words(&mut state);
    wipe_words(&mut working);
    output
}

/// XOR `data` with the ChaCha20 keystream starting at block `counter`.
///
/// Encryption and decryption are the same operation. The call fails with
/// [`Error::OutOfRange`], leaving `data` untouched, when the message would need
/// block counters beyond `u32::MAX`.
pub fn chacha20_xor(
    key: &[u8; KEY_SIZE],
    counter: u32,
    nonce: &[u8; NONCE_SIZE],
    data: &mut [u8],
) -> Result<()> {
    let needed = data.len().div_ceil(BLOCK_SIZE) as u64;
    let available = u64::from(u32::MAX - counter) + 1;
    if needed > available {
        return Err(Error::OutOfRange);
    }
    for (index, chunk) in data.chunks_mut(BLOCK_SIZE).enumerate() {
        // `index < needed <= available`, so the counter never wraps past u32::MAX.
        let block_counter = counter.wrapping_add(index as u32);
        let mut keystream = chacha20_block(key, block_counter, nonce);
        for (byte, key_byte) in chunk.iter_mut().zip(keystream) {
            *byte ^= key_byte;
        }
        wipe_bytes(&mut keystream);
    }
    Ok(())
}

/// A ChaCha20 generator with fast key erasure.
///
/// Each epoch uses one key, zero nonce and block counters `0..REKEY_BLOCKS`.
/// The block at counter `REKEY_BLOCKS` closes the epoch: its first 32 bytes
/// become the next key, the old key is wiped, and its last 32 bytes are
/// output. Because no key is ever reused, the zero nonce never repeats under
/// one key.
///
/// The type deliberately implements neither `Debug` nor `Clone`, so the key
/// cannot be printed or silently duplicated. It wipes its key and buffer on
/// drop.
pub struct ChaChaRng {
    key: [u8; KEY_SIZE],
    /// Counter of the next keystream block in the current epoch.
    counter: u32,
    /// Keystream blocks left before the next block must rekey.
    blocks_left: u32,
    /// The most recent keystream block; `offset` marks the next unread byte.
    buffer: [u8; BLOCK_SIZE],
    offset: usize,
}

impl ChaChaRng {
    /// Create a generator keyed by `seed`.
    ///
    /// The caller's copy of `seed` is not wiped by this function.
    pub fn from_seed(seed: [u8; KEY_SIZE]) -> Self {
        Self {
            key: seed,
            counter: 0,
            blocks_left: REKEY_BLOCKS,
            buffer: [0; BLOCK_SIZE],
            offset: BLOCK_SIZE,
        }
    }

    /// Fill `out` with keystream bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut rest = out;
        while !rest.is_empty() {
            if self.offset == BLOCK_SIZE {
                self.refill();
            }
            let take = (BLOCK_SIZE - self.offset).min(rest.len());
            let (head, tail) = rest.split_at_mut(take);
            head.copy_from_slice(&self.buffer[self.offset..self.offset + take]);
            self.offset += take;
            rest = tail;
        }
    }

    /// Return the next 8 bytes of output as a little-endian `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    /// Return a uniformly distributed value in `0..bound`.
    ///
    /// Values that fall in the final partial bucket of the 64-bit range are
    /// rejected and redrawn, so every residue is equally likely. Fails with
    /// [`Error::InvalidInput`] when `bound` is zero.
    pub fn below(&mut self, bound: u64) -> Result<u64> {
        if bound == 0 {
            return Err(Error::InvalidInput);
        }
        let accept = rejection_limit(bound);
        loop {
            let value = self.next_u64();
            if value <= accept {
                return Ok(value % bound);
            }
        }
    }

    fn refill(&mut self) {
        if self.blocks_left == 0 {
            // Fast key erasure: the closing block supplies the next key, and the
            // old key is overwritten in place.
            let mut closing = chacha20_block(&self.key, self.counter, &ZERO_NONCE);
            self.key.copy_from_slice(&closing[..KEY_SIZE]);
            wipe_bytes(&mut closing[..KEY_SIZE]);
            self.buffer = closing;
            self.offset = KEY_SIZE;
            self.counter = 0;
            self.blocks_left = REKEY_BLOCKS;
        } else {
            self.buffer = chacha20_block(&self.key, self.counter, &ZERO_NONCE);
            self.offset = 0;
            self.counter += 1;
            self.blocks_left -= 1;
        }
    }
}

impl Drop for ChaChaRng {
    fn drop(&mut self) {
        wipe_bytes(&mut self.key);
        wipe_bytes(&mut self.buffer);
    }
}

/// The largest draw accepted by [`ChaChaRng::below`] for `bound`.
///
/// Draws `0..=limit` cover exactly `(limit + 1)` values, which is a multiple of
/// `bound`, so reducing them modulo `bound` is unbiased.
fn rejection_limit(bound: u64) -> u64 {
    // 2^64 mod bound, computed without overflowing u64.
    let remainder = ((u64::MAX % bound) + 1) % bound;
    u64::MAX - remainder
}

/// Choose a random base for a region of `size` bytes inside a user window.
///
/// The base is uniformly chosen from the `align`-aligned bases `b` with
/// `low <= b` and `b + size <= high`, so `[base, base + size)` lies inside
/// `[low, high)`.
///
/// Errors:
/// - [`Error::InvalidInput`] if `align` is not a power of two of at least
///   [`PAGE_SIZE`], or if `size` is zero.
/// - [`Error::BadAddress`] if `low` is zero, or if `high` exceeds
///   [`USER_ADDRESS_LIMIT`]. A base of zero is never produced.
/// - [`Error::OutOfRange`] if `high` is below `size`, if the window is empty,
///   or if no aligned slot fits. Arithmetic is checked throughout.
pub fn aslr_base(rng: &mut ChaChaRng, low: u64, high: u64, align: u64, size: u64) -> Result<u64> {
    if !align.is_power_of_two() || align < PAGE_SIZE || size == 0 {
        return Err(Error::InvalidInput);
    }
    if low == 0 || high > USER_ADDRESS_LIMIT {
        return Err(Error::BadAddress);
    }
    let mask = align - 1;
    let first = low.checked_add(mask).ok_or(Error::OutOfRange)? & !mask;
    let latest_start = high.checked_sub(size).ok_or(Error::OutOfRange)?;
    let last = latest_start & !mask;
    if last < first {
        return Err(Error::OutOfRange);
    }
    let slots = ((last - first) / align)
        .checked_add(1)
        .ok_or(Error::OutOfRange)?;
    let index = rng.below(slots)?;
    let offset = index.checked_mul(align).ok_or(Error::OutOfRange)?;
    first.checked_add(offset).ok_or(Error::OutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 section 2.3.2 and 2.4.2 key: 00:01:02:...:1f.
    const RFC_KEY: [u8; KEY_SIZE] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    /// RFC 8439 section 2.3.2 nonce: 00:00:00:09:00:00:00:4a:00:00:00:00.
    const BLOCK_NONCE: [u8; NONCE_SIZE] = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];

    /// RFC 8439 section 2.4.2 nonce: 00:00:00:00:00:00:00:4a:00:00:00:00.
    const ENCRYPT_NONCE: [u8; NONCE_SIZE] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];

    /// RFC 8439 section 2.3.2 serialized block for counter 1.
    const BLOCK_EXPECTED: [u8; BLOCK_SIZE] = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71,
        0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4,
        0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9,
        0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8,
        0xa2, 0x50, 0x3c, 0x4e,
    ];

    /// RFC 8439 section 2.4.2 plaintext (114 bytes).
    const PLAINTEXT: &[u8; 114] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    /// RFC 8439 section 2.4.2 ciphertext for counter 1.
    const CIPHERTEXT: [u8; 114] = [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69,
        0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f,
        0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd,
        0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
        0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e,
        0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c,
        0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4,
        0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d,
    ];

    #[test]
    fn rfc8439_block_function_vector() {
        assert_eq!(chacha20_block(&RFC_KEY, 1, &BLOCK_NONCE), BLOCK_EXPECTED);
    }

    #[test]
    fn rfc8439_encryption_vector() {
        let mut data = *PLAINTEXT;
        chacha20_xor(&RFC_KEY, 1, &ENCRYPT_NONCE, &mut data).unwrap();
        assert_eq!(data, CIPHERTEXT);

        chacha20_xor(&RFC_KEY, 1, &ENCRYPT_NONCE, &mut data).unwrap();
        assert_eq!(&data, PLAINTEXT);
    }

    #[test]
    fn xor_refuses_counter_exhaustion_without_touching_data() {
        let mut data = [0u8; 65];
        assert_eq!(
            chacha20_xor(&RFC_KEY, u32::MAX, &ZERO_NONCE, &mut data),
            Err(Error::OutOfRange)
        );
        assert_eq!(data, [0u8; 65]);

        let mut last = [0u8; 64];
        assert_eq!(
            chacha20_xor(&RFC_KEY, u32::MAX, &ZERO_NONCE, &mut last),
            Ok(())
        );
    }

    #[test]
    fn first_epoch_block_is_keystream_under_the_seed() {
        let mut rng = ChaChaRng::from_seed(RFC_KEY);
        let mut out = [0u8; BLOCK_SIZE];
        rng.fill(&mut out);
        assert_eq!(out, chacha20_block(&RFC_KEY, 0, &ZERO_NONCE));
    }

    #[test]
    fn same_seed_repeats_and_different_seed_diverges() {
        let mut a = ChaChaRng::from_seed(RFC_KEY);
        let mut b = ChaChaRng::from_seed(RFC_KEY);
        let mut other_seed = RFC_KEY;
        other_seed[0] ^= 1;
        let mut c = ChaChaRng::from_seed(other_seed);

        let (mut out_a, mut out_b, mut out_c) = ([0u8; 200], [0u8; 200], [0u8; 200]);
        a.fill(&mut out_a);
        b.fill(&mut out_b);
        c.fill(&mut out_c);
        assert_eq!(out_a, out_b);
        assert_ne!(out_a, out_c);
    }

    #[test]
    fn fill_is_independent_of_chunking() {
        let mut whole = ChaChaRng::from_seed(RFC_KEY);
        let mut split = ChaChaRng::from_seed(RFC_KEY);
        let mut a = [0u8; 300];
        let mut b = [0u8; 300];
        whole.fill(&mut a);

        let mut pos = 0;
        for len in [1, 63, 64, 72, 100] {
            split.fill(&mut b[pos..pos + len]);
            pos += len;
        }
        assert_eq!(pos, b.len());
        assert_eq!(a, b);
    }

    #[test]
    fn next_u64_is_the_little_endian_prefix_of_fill() {
        let mut direct = ChaChaRng::from_seed(RFC_KEY);
        let mut bytes = ChaChaRng::from_seed(RFC_KEY);
        let mut buf = [0u8; 8];
        bytes.fill(&mut buf);
        assert_eq!(direct.next_u64(), u64::from_le_bytes(buf));
    }

    #[test]
    fn rekey_replaces_the_key_after_one_epoch() {
        let mut rng = ChaChaRng::from_seed(RFC_KEY);
        let mut block = [0u8; BLOCK_SIZE];
        for _ in 0..REKEY_BLOCKS {
            rng.fill(&mut block);
        }

        // The closing block is keystream under the old key at counter REKEY_BLOCKS.
        let closing = chacha20_block(&RFC_KEY, REKEY_BLOCKS, &ZERO_NONCE);
        let mut tail = [0u8; KEY_SIZE];
        rng.fill(&mut tail);
        assert_eq!(&tail[..], &closing[KEY_SIZE..]);

        let mut new_key = [0u8; KEY_SIZE];
        new_key.copy_from_slice(&closing[..KEY_SIZE]);
        assert_eq!(rng.key, new_key);
        assert_ne!(rng.key, RFC_KEY);
        assert!(rng.buffer[..KEY_SIZE].iter().all(|&byte| byte == 0));

        // The next epoch restarts at counter 0 under the new key.
        let mut next = [0u8; BLOCK_SIZE];
        rng.fill(&mut next);
        assert_eq!(next, chacha20_block(&new_key, 0, &ZERO_NONCE));
    }

    #[test]
    fn below_rejects_zero_and_is_trivial_for_one() {
        let mut rng = ChaChaRng::from_seed(RFC_KEY);
        assert_eq!(rng.below(0), Err(Error::InvalidInput));
        for _ in 0..100 {
            assert_eq!(rng.below(1), Ok(0));
        }
    }

    #[test]
    fn rejection_limit_accepts_only_whole_buckets() {
        for bound in [2u64, 3, 5, 6, 7, 10, 1000, (1 << 40) + 3, 1 << 63, u64::MAX] {
            let limit = rejection_limit(bound);
            assert_eq!(
                (u128::from(limit) + 1) % u128::from(bound),
                0,
                "bound {bound}"
            );
        }
        assert_eq!(rejection_limit(3), u64::MAX - 1);
        assert_eq!(rejection_limit(1 << 63), u64::MAX);
    }

    #[test]
    fn below_stays_in_range() {
        let mut rng = ChaChaRng::from_seed(RFC_KEY);
        for bound in [2u64, 3, 7, 1000, 1 << 32, (1 << 63) + 1, u64::MAX] {
            for _ in 0..1000 {
                assert!(rng.below(bound).unwrap() < bound);
            }
        }
    }

    #[test]
    fn below_is_unbiased_for_a_small_bound() {
        // A fixed seed makes this deterministic. With 60,000 draws over six
        // buckets the expected count is 10,000 and the standard deviation is
        // about 91, so a 5 percent tolerance is over five sigma.
        const BOUND: u64 = 6;
        const DRAWS: u64 = 60_000;
        let mut rng = ChaChaRng::from_seed(RFC_KEY);
        let mut counts = [0u64; BOUND as usize];
        for _ in 0..DRAWS {
            counts[rng.below(BOUND).unwrap() as usize] += 1;
        }
        let expected = DRAWS / BOUND;
        for count in counts {
            assert!(
                count.abs_diff(expected) * 100 < expected * 5,
                "bucket count {count} far from {expected}"
            );
        }
    }

    #[test]
    fn aslr_base_is_aligned_and_inside_the_window() {
        let mut rng = ChaChaRng::from_seed(RFC_KEY);
        let (low, high) = (0x40_0000u64, 0x7fff_ffff_f000u64);
        let (align, size) = (0x20_0000u64, 0x1_0000u64);
        for _ in 0..10_000 {
            let base = aslr_base(&mut rng, low, high, align, size).unwrap();
            assert_eq!(base % align, 0);
            assert!(base >= low);
            assert!(base + size <= high);
            assert!(base <= USER_ADDRESS_LIMIT - size);
        }
    }

    #[test]
    fn aslr_base_covers_every_slot_roughly_uniformly() {
        // Window 0x10000..0x18800 with page alignment and a one-page region
        // gives exactly eight slots: 0x10000 through 0x17000.
        let mut rng = ChaChaRng::from_seed(RFC_KEY);
        let (low, high) = (0x10000u64, 0x18800u64);
        let mut counts = [0u64; 8];
        for _ in 0..8_000 {
            let base = aslr_base(&mut rng, low, high, PAGE_SIZE, PAGE_SIZE).unwrap();
            counts[((base - low) / PAGE_SIZE) as usize] += 1;
        }
        for count in counts {
            assert!(count.abs_diff(1000) <= 150, "slot count {count}");
        }
    }

    #[test]
    fn aslr_base_with_an_exact_fit_returns_the_window_start() {
        let mut rng = ChaChaRng::from_seed(RFC_KEY);
        for _ in 0..10 {
            let base = aslr_base(&mut rng, 0x20000, 0x22000, PAGE_SIZE, 0x2000).unwrap();
            assert_eq!(base, 0x20000);
        }
    }

    #[test]
    fn aslr_base_rejects_invalid_parameters() {
        let mut rng = ChaChaRng::from_seed(RFC_KEY);
        let (low, high) = (0x40_0000u64, 0x80_0000u64);
        assert_eq!(
            aslr_base(&mut rng, low, high, 0x800, PAGE_SIZE),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            aslr_base(&mut rng, low, high, 0x3000, PAGE_SIZE),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            aslr_base(&mut rng, low, high, 0, PAGE_SIZE),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            aslr_base(&mut rng, low, high, PAGE_SIZE, 0),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            aslr_base(&mut rng, 0, high, PAGE_SIZE, PAGE_SIZE),
            Err(Error::BadAddress)
        );
        assert_eq!(
            aslr_base(&mut rng, low, USER_ADDRESS_LIMIT + 1, PAGE_SIZE, PAGE_SIZE),
            Err(Error::BadAddress)
        );
    }

    #[test]
    fn aslr_base_reports_when_no_slot_fits() {
        let mut rng = ChaChaRng::from_seed(RFC_KEY);
        // Region larger than the window.
        assert_eq!(
            aslr_base(&mut rng, 0x10000, 0x11000, PAGE_SIZE, 0x2000),
            Err(Error::OutOfRange)
        );
        // Region larger than the high bound itself.
        assert_eq!(
            aslr_base(&mut rng, 0x1000, 0x1000, PAGE_SIZE, 0x2000),
            Err(Error::OutOfRange)
        );
        // Alignment pushes the first slot past the last one.
        assert_eq!(
            aslr_base(&mut rng, 0x1001, 0x2000, PAGE_SIZE, PAGE_SIZE),
            Err(Error::OutOfRange)
        );
        // Inverted window.
        assert_eq!(
            aslr_base(&mut rng, 0x20000, 0x10000, PAGE_SIZE, PAGE_SIZE),
            Err(Error::OutOfRange)
        );
        // A size that cannot be represented must not wrap.
        assert_eq!(
            aslr_base(&mut rng, 0x10000, 0x20000, PAGE_SIZE, u64::MAX),
            Err(Error::OutOfRange)
        );
    }
}
