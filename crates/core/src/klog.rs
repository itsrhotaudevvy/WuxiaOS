//! Sequenced kernel log ring with loss reporting.
//!
//! Each record is a fixed header (sequence, tick, level, flags and message
//! length) followed by the message bytes. Records are appended to a byte ring
//! of `BYTES` bytes. When an append does not fit, the oldest whole records are
//! evicted; a record is never partially overwritten. A message longer than
//! `MAX_MESSAGE` is truncated and flagged.
//!
//! Sequence numbers are contiguous, so a reader needs to remember only the
//! next sequence it wants. A reader that has fallen behind the oldest retained
//! record is told how many records it missed before it resumes.

use crate::{Error, Result};

/// Largest stored message in bytes. Longer messages are truncated.
pub const MAX_MESSAGE: usize = 1024;

/// Bytes in each record header: sequence, tick, level, flags and length.
const HEADER: usize = 8 + 8 + 1 + 1 + 2;
const SEQ_AT: usize = 0;
const TICK_AT: usize = 8;
const LEVEL_AT: usize = 16;
const FLAGS_AT: usize = 17;
const LEN_AT: usize = 18;
const FLAG_TRUNCATED: u8 = 1;

/// Syslog-style severity, from most to least severe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Level {
    /// The system is unusable.
    Emergency = 0,
    /// Action must be taken immediately.
    Alert = 1,
    /// A critical condition.
    Critical = 2,
    /// An error condition.
    Error = 3,
    /// A warning condition.
    Warning = 4,
    /// A normal but significant condition.
    Notice = 5,
    /// An informational message.
    Info = 6,
    /// A debugging message.
    Debug = 7,
}

impl Level {
    /// Decode a stored level code. Codes are written only from `Level` values,
    /// so the fallback arm is unreachable for records this module wrote.
    fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            _ => Self::Debug,
        }
    }
}

/// Outcome of one `Reader::read` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadResult {
    /// A record was copied out. `out[..len]` holds its message, and
    /// `truncated` reports that the original message was longer than
    /// `MAX_MESSAGE`.
    Record {
        /// Sequence number of the record.
        seq: u64,
        /// Tick supplied when the record was appended.
        tick: u64,
        /// Severity supplied when the record was appended.
        level: Level,
        /// Number of message bytes copied into `out`.
        len: usize,
        /// Whether the stored message was cut short.
        truncated: bool,
    },
    /// Records were evicted before this reader reached them. The reader has
    /// already advanced past them, so the next read returns the oldest
    /// retained record.
    Lost {
        /// Number of records evicted before the reader got to them.
        missed: u64,
    },
    /// The reader has caught up with the newest record.
    Empty,
}

/// A read position, identified by the next sequence number wanted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Reader {
    next_seq: u64,
}

impl Reader {
    /// A reader that wants every record from sequence 0 onward.
    pub const fn new() -> Self {
        Self { next_seq: 0 }
    }

    /// Sequence number of the next record this reader wants.
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Read the next record into `out`, or report loss or emptiness.
    ///
    /// If records were evicted before this reader reached them, the call
    /// returns `Lost` and moves the reader to the oldest retained record
    /// without copying anything. Locating a record walks forward from the
    /// oldest retained record, so the cost grows with the number of retained
    /// records before it.
    pub fn read<const BYTES: usize>(
        &mut self,
        log: &KernelLog<BYTES>,
        out: &mut [u8; MAX_MESSAGE],
    ) -> ReadResult {
        if self.next_seq < log.oldest_seq {
            let missed = log.oldest_seq - self.next_seq;
            self.next_seq = log.oldest_seq;
            return ReadResult::Lost { missed };
        }
        if self.next_seq >= log.next_seq {
            return ReadResult::Empty;
        }

        let pos = log.position_of(self.next_seq);
        let seq = u64::from_le_bytes(log.read_bytes(pos + SEQ_AT));
        let tick = u64::from_le_bytes(log.read_bytes(pos + TICK_AT));
        let level = Level::from_code(log.byte_at(pos + LEVEL_AT));
        let flags = log.byte_at(pos + FLAGS_AT);
        let len = log.record_len_at(pos);
        let body = pos + HEADER;
        for (i, slot) in out[..len].iter_mut().enumerate() {
            *slot = log.byte_at(body + i);
        }

        debug_assert_eq!(seq, self.next_seq);
        self.next_seq = seq + 1;
        ReadResult::Record {
            seq,
            tick,
            level,
            len,
            truncated: (flags & FLAG_TRUNCATED) != 0,
        }
    }
}

/// A fixed-capacity ring of sequenced log records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelLog<const BYTES: usize> {
    buffer: [u8; BYTES],
    /// Ring offset of the oldest retained record.
    head: usize,
    /// Bytes occupied by retained records, headers included.
    used: usize,
    /// Sequence number of the oldest retained record.
    oldest_seq: u64,
    /// Sequence number the next append receives.
    next_seq: u64,
}

impl<const BYTES: usize> Default for KernelLog<BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BYTES: usize> KernelLog<BYTES> {
    /// Construct an empty log. The ring must hold one maximum-size record,
    /// which is checked when the log is instantiated.
    pub const fn new() -> Self {
        const {
            assert!(
                BYTES >= HEADER + MAX_MESSAGE,
                "a kernel log must hold one maximum-size record"
            );
        }
        Self {
            buffer: [0; BYTES],
            head: 0,
            used: 0,
            oldest_seq: 0,
            next_seq: 0,
        }
    }

    /// Sequence number of the oldest retained record. Equal to `next_seq`
    /// when the log holds no records.
    pub const fn oldest_seq(&self) -> u64 {
        self.oldest_seq
    }

    /// Sequence number the next append will receive.
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Append a record and return its sequence number.
    ///
    /// Messages longer than `MAX_MESSAGE` are stored truncated and flagged.
    /// Oldest whole records are evicted until the new record fits. Fails with
    /// `OutOfRange`, leaving the log unchanged, when sequence numbers are
    /// exhausted.
    pub fn append(&mut self, tick: u64, level: Level, message: &[u8]) -> Result<u64> {
        let seq = self.next_seq;
        let next = seq.checked_add(1).ok_or(Error::OutOfRange)?;
        let stored = message.len().min(MAX_MESSAGE);
        let truncated = message.len() > MAX_MESSAGE;
        let size = HEADER + stored;

        while self.used + size > BYTES {
            self.evict_oldest();
        }

        let start = self.wrap(self.head + self.used);
        let mut header = [0u8; HEADER];
        header[SEQ_AT..SEQ_AT + 8].copy_from_slice(&seq.to_le_bytes());
        header[TICK_AT..TICK_AT + 8].copy_from_slice(&tick.to_le_bytes());
        header[LEVEL_AT] = level as u8;
        header[FLAGS_AT] = if truncated { FLAG_TRUNCATED } else { 0 };
        header[LEN_AT..LEN_AT + 2].copy_from_slice(&(stored as u16).to_le_bytes());
        for (i, &byte) in header.iter().enumerate() {
            self.write_byte(start + i, byte);
        }
        let body = self.wrap(start + HEADER);
        for (i, &byte) in message[..stored].iter().enumerate() {
            self.write_byte(body + i, byte);
        }

        self.used += size;
        self.next_seq = next;
        Ok(seq)
    }

    /// Drop the oldest retained record. Callers ensure one exists.
    fn evict_oldest(&mut self) {
        let size = HEADER + self.record_len_at(self.head);
        self.head = self.wrap(self.head + size);
        self.used -= size;
        self.oldest_seq += 1;
    }

    /// Ring position of the retained record with sequence `seq`, which must
    /// lie in `oldest_seq..next_seq`.
    fn position_of(&self, seq: u64) -> usize {
        let mut pos = self.head;
        for _ in self.oldest_seq..seq {
            pos = self.wrap(pos + HEADER + self.record_len_at(pos));
        }
        pos
    }

    /// Message length stored in the header at ring position `pos`.
    fn record_len_at(&self, pos: usize) -> usize {
        usize::from(u16::from_le_bytes(self.read_bytes(pos + LEN_AT)))
    }

    fn read_bytes<const N: usize>(&self, pos: usize) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.byte_at(pos + i);
        }
        out
    }

    fn byte_at(&self, pos: usize) -> u8 {
        self.buffer[self.wrap(pos)]
    }

    fn write_byte(&mut self, pos: usize, byte: u8) {
        let slot = self.wrap(pos);
        self.buffer[slot] = byte;
    }

    /// Reduce an index in `0..2 * BYTES` to `0..BYTES`.
    fn wrap(&self, index: usize) -> usize {
        if index >= BYTES { index - BYTES } else { index }
    }
}

/// Format one record as `<level>[tick] message\n` into `out`.
///
/// Returns the number of bytes written. Fails with `OutOfRange` when `out` is
/// too small, and then `out` may hold a partial line.
pub fn format_line(level: Level, tick: u64, message: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut cursor = Cursor { out, at: 0 };
    cursor.put(b"<")?;
    cursor.put(&[b'0' + level as u8])?;
    cursor.put(b">[")?;
    put_decimal(&mut cursor, tick)?;
    cursor.put(b"] ")?;
    cursor.put(message)?;
    cursor.put(b"\n")?;
    Ok(cursor.at)
}

/// Bounded writer over an output buffer.
struct Cursor<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Cursor<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.at.checked_add(bytes.len()).ok_or(Error::OutOfRange)?;
        let dst = self.out.get_mut(self.at..end).ok_or(Error::OutOfRange)?;
        dst.copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }
}

fn put_decimal(cursor: &mut Cursor<'_>, mut value: u64) -> Result<()> {
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
    cursor.put(&digits[start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic linear congruential generator for the long-run test.
    struct Lcg(u64);

    impl Lcg {
        fn step(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.step() % bound as u64) as usize
        }
    }

    /// The smallest legal ring: one maximum-size record.
    const MIN_BYTES: usize = HEADER + MAX_MESSAGE;

    const LEVELS: [Level; 8] = [
        Level::Emergency,
        Level::Alert,
        Level::Critical,
        Level::Error,
        Level::Warning,
        Level::Notice,
        Level::Info,
        Level::Debug,
    ];

    /// Fill `out` with bytes that depend on the sequence and position, so a
    /// record delivered under the wrong sequence fails the comparison.
    fn fill(seq: u64, out: &mut [u8]) {
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = ((seq ^ i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8;
        }
    }

    fn read_one<const BYTES: usize>(reader: &mut Reader, log: &KernelLog<BYTES>) -> ReadResult {
        let mut out = [0u8; MAX_MESSAGE];
        reader.read(log, &mut out)
    }

    #[test]
    fn a_new_log_is_empty_and_its_reader_sees_empty() {
        let log = KernelLog::<MIN_BYTES>::new();
        assert_eq!(log.oldest_seq(), 0);
        assert_eq!(log.next_seq(), 0);
        let mut reader = Reader::new();
        assert_eq!(reader.next_seq(), 0);
        assert_eq!(read_one(&mut reader, &log), ReadResult::Empty);
        assert_eq!(reader.next_seq(), 0);
    }

    #[test]
    fn records_return_their_sequence_tick_level_and_bytes() {
        let mut log = KernelLog::<MIN_BYTES>::new();
        assert_eq!(log.append(7, LEVELS[4], b"disk slow"), Ok(0));
        assert_eq!(log.append(9, LEVELS[6], b"boot ok"), Ok(1));
        assert_eq!(log.next_seq(), 2);

        let mut reader = Reader::new();
        let mut out = [0u8; MAX_MESSAGE];
        assert_eq!(
            reader.read(&log, &mut out),
            ReadResult::Record {
                seq: 0,
                tick: 7,
                level: Level::Warning,
                len: 9,
                truncated: false,
            }
        );
        assert_eq!(&out[..9], b"disk slow");
        assert_eq!(
            reader.read(&log, &mut out),
            ReadResult::Record {
                seq: 1,
                tick: 9,
                level: Level::Info,
                len: 7,
                truncated: false,
            }
        );
        assert_eq!(&out[..7], b"boot ok");
        assert_eq!(reader.read(&log, &mut out), ReadResult::Empty);
    }

    #[test]
    fn every_level_survives_storage() {
        let mut log = KernelLog::<MIN_BYTES>::new();
        for level in LEVELS {
            log.append(0, level, b"x").unwrap();
        }
        let mut reader = Reader::new();
        for (seq, level) in LEVELS.into_iter().enumerate() {
            match read_one(&mut reader, &log) {
                ReadResult::Record {
                    seq: got,
                    level: got_level,
                    ..
                } => {
                    assert_eq!(got, seq as u64);
                    assert_eq!(got_level, level);
                }
                other => panic!("expected a record, got {other:?}"),
            }
        }
    }

    #[test]
    fn zero_length_messages_are_valid_records() {
        let mut log = KernelLog::<MIN_BYTES>::new();
        assert_eq!(log.append(3, LEVELS[6], b""), Ok(0));
        let mut reader = Reader::new();
        assert_eq!(
            read_one(&mut reader, &log),
            ReadResult::Record {
                seq: 0,
                tick: 3,
                level: Level::Info,
                len: 0,
                truncated: false,
            }
        );
        assert_eq!(read_one(&mut reader, &log), ReadResult::Empty);
    }

    #[test]
    fn oversized_messages_are_truncated_and_flagged() {
        let mut log = KernelLog::<MIN_BYTES>::new();
        let mut message = [0u8; MAX_MESSAGE + 476];
        fill(5, &mut message);
        assert_eq!(log.append(1, LEVELS[3], &message), Ok(0));

        let mut reader = Reader::new();
        let mut out = [0u8; MAX_MESSAGE];
        assert_eq!(
            reader.read(&log, &mut out),
            ReadResult::Record {
                seq: 0,
                tick: 1,
                level: Level::Error,
                len: MAX_MESSAGE,
                truncated: true,
            }
        );
        assert_eq!(out[..], message[..MAX_MESSAGE]);

        // The truncated record is whole: the next record is unaffected.
        assert_eq!(log.append(2, LEVELS[7], b"after"), Ok(1));
        assert_eq!(
            reader.read(&log, &mut out),
            ReadResult::Record {
                seq: 1,
                tick: 2,
                level: Level::Debug,
                len: 5,
                truncated: false,
            }
        );
        assert_eq!(&out[..5], b"after");
    }

    #[test]
    fn a_message_of_exactly_the_maximum_length_is_not_flagged() {
        let mut log = KernelLog::<MIN_BYTES>::new();
        let mut message = [0u8; MAX_MESSAGE];
        fill(8, &mut message);
        log.append(0, LEVELS[5], &message).unwrap();
        let mut reader = Reader::new();
        let mut out = [0u8; MAX_MESSAGE];
        assert_eq!(
            reader.read(&log, &mut out),
            ReadResult::Record {
                seq: 0,
                tick: 0,
                level: Level::Notice,
                len: MAX_MESSAGE,
                truncated: false,
            }
        );
        assert_eq!(out, message);
    }

    #[test]
    fn a_full_ring_evicts_whole_oldest_records() {
        // A 100-byte message occupies 120 bytes, so eight records fit in 1044.
        let mut log = KernelLog::<MIN_BYTES>::new();
        let mut message = [0u8; 100];
        for seq in 0..9u64 {
            fill(seq, &mut message);
            assert_eq!(log.append(seq, LEVELS[6], &message), Ok(seq));
        }
        assert_eq!(log.next_seq(), 9);
        assert_eq!(log.oldest_seq(), 1);

        let mut reader = Reader::new();
        assert_eq!(read_one(&mut reader, &log), ReadResult::Lost { missed: 1 });
        let mut out = [0u8; MAX_MESSAGE];
        for seq in 1..9u64 {
            assert_eq!(
                reader.read(&log, &mut out),
                ReadResult::Record {
                    seq,
                    tick: seq,
                    level: Level::Info,
                    len: 100,
                    truncated: false,
                }
            );
            fill(seq, &mut message);
            assert_eq!(out[..100], message[..]);
        }
        assert_eq!(reader.read(&log, &mut out), ReadResult::Empty);
    }

    #[test]
    fn a_reader_that_keeps_up_never_sees_loss_across_many_wraps() {
        let mut log = KernelLog::<MIN_BYTES>::new();
        let mut reader = Reader::new();
        let mut message = [0u8; 100];
        let mut out = [0u8; MAX_MESSAGE];
        // 60 records of 120 bytes wrap the 1044-byte ring several times.
        for seq in 0..60u64 {
            fill(seq, &mut message);
            log.append(seq, LEVELS[6], &message).unwrap();
            assert_eq!(
                reader.read(&log, &mut out),
                ReadResult::Record {
                    seq,
                    tick: seq,
                    level: Level::Info,
                    len: 100,
                    truncated: false,
                }
            );
            fill(seq, &mut message);
            assert_eq!(out[..100], message[..]);
        }
        assert_eq!(reader.read(&log, &mut out), ReadResult::Empty);
    }

    #[test]
    fn a_reader_behind_the_oldest_record_is_told_what_it_missed() {
        let mut log = KernelLog::<MIN_BYTES>::new();
        let message = [0x41u8; 100];
        let mut reader = Reader::new();
        let mut out = [0u8; MAX_MESSAGE];

        for _ in 0..2 {
            log.append(0, LEVELS[6], &message).unwrap();
        }
        assert_eq!(
            reader.read(&log, &mut out),
            ReadResult::Record {
                seq: 0,
                tick: 0,
                level: Level::Info,
                len: 100,
                truncated: false,
            }
        );
        // The reader is now at sequence 1. Twenty more records (sequences 2
        // through 21) leave only the newest eight, so sequences 1 through 13
        // are gone and the oldest retained record is 14.
        for _ in 0..20 {
            log.append(0, LEVELS[6], &message).unwrap();
        }
        assert_eq!(log.oldest_seq(), 14);
        assert_eq!(reader.next_seq(), 1);
        assert_eq!(reader.read(&log, &mut out), ReadResult::Lost { missed: 13 });
        assert_eq!(reader.next_seq(), 14);
        assert_eq!(
            reader.read(&log, &mut out),
            ReadResult::Record {
                seq: 14,
                tick: 0,
                level: Level::Info,
                len: 100,
                truncated: false,
            }
        );
        assert_eq!(reader.next_seq(), 15);
    }

    #[test]
    fn a_reader_at_the_oldest_record_loses_nothing() {
        let mut log = KernelLog::<MIN_BYTES>::new();
        let message = [0x42u8; 100];
        for _ in 0..9 {
            log.append(0, LEVELS[6], &message).unwrap();
        }
        assert_eq!(log.oldest_seq(), 1);
        let mut reader = Reader { next_seq: 1 };
        let mut out = [0u8; MAX_MESSAGE];
        assert!(matches!(
            reader.read(&log, &mut out),
            ReadResult::Record { seq: 1, .. }
        ));
    }

    #[test]
    fn a_reader_ahead_of_the_log_sees_empty_until_it_catches_up() {
        let mut log = KernelLog::<MIN_BYTES>::new();
        let mut reader = Reader { next_seq: 5 };
        assert_eq!(read_one(&mut reader, &log), ReadResult::Empty);
        assert_eq!(reader.next_seq(), 5);
        log.append(0, LEVELS[6], b"a").unwrap();
        assert_eq!(read_one(&mut reader, &log), ReadResult::Empty);
    }

    #[test]
    fn append_fails_without_changes_when_sequence_space_is_exhausted() {
        let mut log = KernelLog::<MIN_BYTES>::new();
        log.next_seq = u64::MAX - 1;
        log.oldest_seq = u64::MAX - 1;
        assert_eq!(log.append(0, LEVELS[6], b"last"), Ok(u64::MAX - 1));
        let before = log.clone();
        assert_eq!(log.append(0, LEVELS[6], b"none"), Err(Error::OutOfRange));
        assert_eq!(log, before);
    }

    #[test]
    fn format_line_writes_level_tick_message_and_newline() {
        let mut out = [0u8; 64];
        let len = format_line(LEVELS[3], 42, b"boot ok", &mut out).unwrap();
        assert_eq!(&out[..len], b"<3>[42] boot ok\n");
    }

    #[test]
    fn format_line_renders_extreme_ticks_and_empty_messages() {
        let mut out = [0u8; 64];
        let len = format_line(LEVELS[7], u64::MAX, b"", &mut out).unwrap();
        assert_eq!(&out[..len], b"<7>[18446744073709551615] \n");
        let len = format_line(LEVELS[0], 0, b"", &mut out).unwrap();
        assert_eq!(&out[..len], b"<0>[0] \n");
    }

    #[test]
    fn format_line_rejects_a_short_buffer() {
        let line = b"<6>[10] hi\n";
        let mut exact = [0u8; 11];
        assert_eq!(format_line(LEVELS[6], 10, b"hi", &mut exact), Ok(11));
        assert_eq!(&exact[..], &line[..]);
        let mut short = [0u8; 10];
        assert_eq!(
            format_line(LEVELS[6], 10, b"hi", &mut short),
            Err(Error::OutOfRange)
        );
    }

    /// Length of the stored message for a record appended with `len` bytes.
    fn stored_len(len: usize) -> usize {
        len.min(MAX_MESSAGE)
    }

    /// Oldest sequence retained when `next` records exist, derived from the
    /// byte budget alone: the longest suffix whose records fit in `bytes`.
    fn model_oldest(lens: &[usize; 1024], next: u64, bytes: usize) -> u64 {
        let mut used = 0usize;
        let mut seq = next;
        while seq > 0 {
            let size = HEADER + stored_len(lens[((seq - 1) % 1024) as usize]);
            if used + size > bytes {
                break;
            }
            used += size;
            seq -= 1;
        }
        seq
    }

    #[test]
    fn long_wraparound_run_checks_sequence_and_loss_accounting() {
        const BYTES: usize = 4096;
        const STEPS: u64 = 30_000;

        let mut log = KernelLog::<BYTES>::new();
        let mut reader = Reader::new();
        let mut rng = Lcg(0x5EED_1234);
        // Message length by sequence, indexed modulo 1024. More than 200
        // records never fit in 4096 bytes, so no live entry is overwritten.
        let mut lens = [0usize; 1024];
        let mut payload = [0u8; MAX_MESSAGE + 100];
        let mut expect = [0u8; MAX_MESSAGE + 100];
        let mut out = [0u8; MAX_MESSAGE];

        let mut expected = 0u64;
        let mut delivered = 0u64;
        let mut lost_total = 0u64;
        let mut lost_events = 0u64;

        for step in 0..STEPS {
            // Append one record with a mostly short length and occasional long ones.
            let len = if rng.below(16) == 0 {
                rng.below(1101)
            } else {
                rng.below(200)
            };
            let seq = log.next_seq();
            fill(seq, &mut payload[..len]);
            let tick = seq.wrapping_mul(3).wrapping_add(5);
            let level = LEVELS[(seq % 8) as usize];
            assert_eq!(
                log.append(tick, level, &payload[..len]),
                Ok(seq),
                "step {step}"
            );
            lens[(seq % 1024) as usize] = len;

            // The log must evict exactly the oldest whole records the byte
            // budget requires.
            let model = model_oldest(&lens, log.next_seq(), BYTES);
            assert_eq!(log.oldest_seq(), model, "step {step}");

            // The reader drains in bursts, and pauses for stretches so that
            // it falls behind and loss occurs.
            let drains = if step % 1000 < 300 { 0 } else { rng.below(3) };
            for _ in 0..drains {
                match reader.read(&log, &mut out) {
                    ReadResult::Lost { missed } => {
                        let oldest = log.oldest_seq();
                        assert!(missed > 0, "step {step}");
                        assert_eq!(missed, oldest - expected, "step {step}");
                        lost_total += missed;
                        lost_events += 1;
                        expected = oldest;
                    }
                    ReadResult::Record {
                        seq: got,
                        tick,
                        level,
                        len,
                        truncated,
                    } => {
                        assert_eq!(got, expected, "step {step}");
                        let want = lens[(got % 1024) as usize];
                        assert_eq!(len, stored_len(want), "step {step}");
                        assert_eq!(truncated, want > MAX_MESSAGE, "step {step}");
                        assert_eq!(tick, got.wrapping_mul(3).wrapping_add(5), "step {step}");
                        assert_eq!(level, LEVELS[(got % 8) as usize], "step {step}");
                        fill(got, &mut expect[..len]);
                        assert_eq!(out[..len], expect[..len], "step {step}");
                        expected += 1;
                        delivered += 1;
                    }
                    ReadResult::Empty => {
                        assert_eq!(expected, log.next_seq(), "step {step}");
                        break;
                    }
                }
            }
        }

        // Drain the rest. Every sequence number is either delivered or counted
        // as lost, so the two totals must account for every append.
        loop {
            match reader.read(&log, &mut out) {
                ReadResult::Lost { missed } => {
                    assert_eq!(missed, log.oldest_seq() - expected);
                    lost_total += missed;
                    lost_events += 1;
                    expected = log.oldest_seq();
                }
                ReadResult::Record { seq: got, .. } => {
                    assert_eq!(got, expected);
                    expected += 1;
                    delivered += 1;
                }
                ReadResult::Empty => break,
            }
        }
        assert_eq!(expected, STEPS);
        assert_eq!(delivered + lost_total, STEPS);
        assert!(lost_events > 0, "the run must exercise loss");
        assert!(delivered > 0);
    }
}
