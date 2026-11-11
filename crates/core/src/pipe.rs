//! POSIX pipe model as a fixed-capacity byte ring buffer.
//!
//! A pipe carries bytes from writer ends to reader ends. Reads report end of
//! file only after every writer has closed and the buffer has drained, writes
//! to a pipe without readers report a broken pipe, and writes of at most
//! `PIPE_BUF` bytes are never split or interleaved. Blocking is not modelled
//! here: the scheduler retries an operation that reports `WouldBlock`.

use crate::{Error, Result};

/// POSIX lower bound on the largest atomic pipe write.
pub const MAX_PIPE_BUF: usize = 512;

/// Outcome of a write to a pipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeWrite {
    /// This many bytes were stored. The count is nonzero unless the write
    /// itself was empty.
    Wrote(usize),
    /// The buffer cannot take the write now; retry after readers drain it.
    WouldBlock,
    /// No reader end exists, so the writer receives EPIPE and SIGPIPE.
    BrokenPipe,
}

/// Outcome of a read from a pipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeRead {
    /// This many bytes were copied out. The count is nonzero unless the read
    /// itself was into an empty buffer.
    Read(usize),
    /// The buffer is empty but writers remain; retry after they write.
    WouldBlock,
    /// The buffer is empty and no writer end exists.
    EndOfFile,
}

/// A pipe with a fixed byte capacity and counted reader and writer ends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pipe<const CAP: usize> {
    buffer: [u8; CAP],
    head: usize,
    len: usize,
    readers: usize,
    writers: usize,
}

impl<const CAP: usize> Default for Pipe<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> Pipe<CAP> {
    /// Largest write that is guaranteed atomic: `min(CAP, MAX_PIPE_BUF)`.
    pub const PIPE_BUF: usize = if CAP < MAX_PIPE_BUF {
        CAP
    } else {
        MAX_PIPE_BUF
    };

    /// Construct an empty pipe with no reader or writer ends.
    pub const fn new() -> Self {
        Self {
            buffer: [0; CAP],
            head: 0,
            len: 0,
            readers: 0,
            writers: 0,
        }
    }

    /// Register a new reader end.
    pub fn add_reader(&mut self) -> Result<()> {
        self.readers = self.readers.checked_add(1).ok_or(Error::OutOfRange)?;
        Ok(())
    }

    /// Register a new writer end.
    pub fn add_writer(&mut self) -> Result<()> {
        self.writers = self.writers.checked_add(1).ok_or(Error::OutOfRange)?;
        Ok(())
    }

    /// Release a reader end, rejecting the close when none is registered.
    pub fn close_reader(&mut self) -> Result<()> {
        self.readers = self.readers.checked_sub(1).ok_or(Error::InvalidState)?;
        Ok(())
    }

    /// Release a writer end, rejecting the close when none is registered.
    pub fn close_writer(&mut self) -> Result<()> {
        self.writers = self.writers.checked_sub(1).ok_or(Error::InvalidState)?;
        Ok(())
    }

    /// Number of registered reader ends.
    pub fn readers(&self) -> usize {
        self.readers
    }

    /// Number of registered writer ends.
    pub fn writers(&self) -> usize {
        self.writers
    }

    /// Write `data` into the pipe.
    ///
    /// An empty write returns `Wrote(0)` without changing state. A write of at
    /// most `PIPE_BUF` bytes either stores all of its bytes or reports
    /// `WouldBlock`. A longer write stores as many bytes as fit, and reports
    /// `WouldBlock` only when no room is left.
    pub fn write(&mut self, data: &[u8]) -> PipeWrite {
        if data.is_empty() {
            return PipeWrite::Wrote(0);
        }
        if self.readers == 0 {
            return PipeWrite::BrokenPipe;
        }
        let available = self.available();
        if data.len() <= Self::PIPE_BUF && data.len() > available {
            return PipeWrite::WouldBlock;
        }
        let count = data.len().min(available);
        if count == 0 {
            return PipeWrite::WouldBlock;
        }
        self.push(&data[..count]);
        PipeWrite::Wrote(count)
    }

    /// Read up to `out.len()` buffered bytes into `out`.
    ///
    /// An empty `out` returns `Read(0)` without changing state. Otherwise an
    /// empty pipe reports end of file once no writer remains, and
    /// `WouldBlock` while one does.
    pub fn read(&mut self, out: &mut [u8]) -> PipeRead {
        if out.is_empty() {
            return PipeRead::Read(0);
        }
        if self.len == 0 {
            return if self.writers == 0 {
                PipeRead::EndOfFile
            } else {
                PipeRead::WouldBlock
            };
        }
        let count = out.len().min(self.len);
        self.pop(&mut out[..count]);
        PipeRead::Read(count)
    }

    /// Number of buffered bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no bytes are buffered.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Free space in bytes.
    pub fn available(&self) -> usize {
        CAP - self.len
    }

    fn push(&mut self, data: &[u8]) {
        let tail = Self::wrap(self.head + self.len);
        let first = data.len().min(CAP - tail);
        self.buffer[tail..tail + first].copy_from_slice(&data[..first]);
        self.buffer[..data.len() - first].copy_from_slice(&data[first..]);
        self.len += data.len();
    }

    fn pop(&mut self, out: &mut [u8]) {
        let count = out.len();
        let first = count.min(CAP - self.head);
        out[..first].copy_from_slice(&self.buffer[self.head..self.head + first]);
        out[first..].copy_from_slice(&self.buffer[..count - first]);
        self.head = Self::wrap(self.head + count);
        self.len -= count;
    }

    /// Reduce an index in `0..2 * CAP` to `0..CAP`.
    fn wrap(index: usize) -> usize {
        if index >= CAP { index - CAP } else { index }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic linear congruential generator for the model test.
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

    #[test]
    fn a_new_pipe_is_empty_and_has_no_ends() {
        let pipe = Pipe::<8>::new();
        assert!(pipe.is_empty());
        assert_eq!(pipe.len(), 0);
        assert_eq!(pipe.available(), 8);
        assert_eq!(pipe.readers(), 0);
        assert_eq!(pipe.writers(), 0);
        assert_eq!(Pipe::<8>::PIPE_BUF, 8);
        assert_eq!(Pipe::<1024>::PIPE_BUF, MAX_PIPE_BUF);
    }

    #[test]
    fn bytes_arrive_in_fifo_order() {
        let mut pipe = Pipe::<16>::new();
        pipe.add_reader().unwrap();
        pipe.add_writer().unwrap();
        assert_eq!(pipe.write(b"abc"), PipeWrite::Wrote(3));
        assert_eq!(pipe.write(b"de"), PipeWrite::Wrote(2));
        assert_eq!(pipe.len(), 5);
        let mut out = [0u8; 8];
        assert_eq!(pipe.read(&mut out), PipeRead::Read(5));
        assert_eq!(&out[..5], b"abcde");
        assert!(pipe.is_empty());
        assert_eq!(pipe.read(&mut out), PipeRead::WouldBlock);
    }

    #[test]
    fn wraparound_holds_across_many_cycles() {
        let mut pipe = Pipe::<5>::new();
        pipe.add_reader().unwrap();
        pipe.add_writer().unwrap();
        let chunks = [1usize, 4, 2, 5, 3];
        let mut next_byte = 0u8;
        let mut expected = 0u8;
        for cycle in 0..200 {
            let chunk = chunks[cycle % chunks.len()];
            let mut sent = [0u8; 5];
            for byte in sent[..chunk].iter_mut() {
                *byte = next_byte;
                next_byte = next_byte.wrapping_add(1);
            }
            assert_eq!(pipe.write(&sent[..chunk]), PipeWrite::Wrote(chunk));
            let mut received = [0u8; 5];
            assert_eq!(pipe.read(&mut received[..chunk]), PipeRead::Read(chunk));
            for &byte in &received[..chunk] {
                assert_eq!(byte, expected);
                expected = expected.wrapping_add(1);
            }
            assert!(pipe.is_empty());
        }
    }

    #[test]
    fn a_write_that_wraps_the_buffer_end_is_read_back_intact() {
        let mut pipe = Pipe::<4>::new();
        pipe.add_reader().unwrap();
        pipe.add_writer().unwrap();
        assert_eq!(pipe.write(b"xyz"), PipeWrite::Wrote(3));
        let mut out = [0u8; 2];
        assert_eq!(pipe.read(&mut out), PipeRead::Read(2));
        assert_eq!(&out, b"xy");
        assert_eq!(pipe.write(b"123"), PipeWrite::Wrote(3));
        let mut all = [0u8; 4];
        assert_eq!(pipe.read(&mut all), PipeRead::Read(4));
        assert_eq!(&all, b"z123");
    }

    #[test]
    fn small_writes_are_atomic_and_large_writes_are_partial() {
        let mut pipe = Pipe::<4>::new();
        pipe.add_reader().unwrap();
        pipe.add_writer().unwrap();
        assert_eq!(pipe.write(b"abc"), PipeWrite::Wrote(3));
        assert_eq!(pipe.write(b"de"), PipeWrite::WouldBlock);
        assert_eq!(pipe.len(), 3);
        assert_eq!(pipe.write(b"d"), PipeWrite::Wrote(1));
        assert_eq!(pipe.write(b"e"), PipeWrite::WouldBlock);
        let mut out = [0u8; 4];
        assert_eq!(pipe.read(&mut out), PipeRead::Read(4));
        assert_eq!(&out, b"abcd");
    }

    #[test]
    fn pipe_buf_atomicity_caps_the_guarantee_at_512_bytes() {
        let mut pipe = Pipe::<1024>::new();
        pipe.add_reader().unwrap();
        pipe.add_writer().unwrap();
        let fill = [7u8; 600];
        assert_eq!(pipe.write(&fill), PipeWrite::Wrote(600));
        assert_eq!(pipe.available(), 424);

        // At most PIPE_BUF bytes must all fit or nothing is stored.
        let block = [9u8; 512];
        assert_eq!(pipe.write(&block), PipeWrite::WouldBlock);
        assert_eq!(pipe.len(), 600);
        assert_eq!(pipe.write(&block[..300]), PipeWrite::Wrote(300));
        assert_eq!(pipe.write(&block[..200]), PipeWrite::WouldBlock);

        // A write above PIPE_BUF may be split and fills the remaining room.
        assert_eq!(pipe.write(&[1u8; 900]), PipeWrite::Wrote(124));
        assert_eq!(pipe.write(&[1u8; 900]), PipeWrite::WouldBlock);
        assert_eq!(pipe.len(), 1024);
    }

    #[test]
    fn end_of_file_only_follows_a_drained_buffer_without_writers() {
        let mut pipe = Pipe::<8>::new();
        pipe.add_reader().unwrap();
        assert_eq!(pipe.read(&mut [0u8; 1]), PipeRead::EndOfFile);

        let mut pipe = Pipe::<8>::new();
        pipe.add_reader().unwrap();
        pipe.add_writer().unwrap();
        assert_eq!(pipe.write(b"xy"), PipeWrite::Wrote(2));
        pipe.close_writer().unwrap();
        let mut one = [0u8; 1];
        assert_eq!(pipe.read(&mut one), PipeRead::Read(1));
        assert_eq!(one[0], b'x');
        assert_eq!(pipe.read(&mut one), PipeRead::Read(1));
        assert_eq!(one[0], b'y');
        assert_eq!(pipe.read(&mut one), PipeRead::EndOfFile);
        assert_eq!(pipe.read(&mut one), PipeRead::EndOfFile);
    }

    #[test]
    fn writes_without_readers_are_a_broken_pipe() {
        let mut pipe = Pipe::<8>::new();
        pipe.add_writer().unwrap();
        assert_eq!(pipe.write(b"a"), PipeWrite::BrokenPipe);
        assert!(pipe.is_empty());

        pipe.add_reader().unwrap();
        assert_eq!(pipe.write(b"a"), PipeWrite::Wrote(1));
        pipe.close_reader().unwrap();
        assert_eq!(pipe.write(b"b"), PipeWrite::BrokenPipe);
        assert_eq!(pipe.len(), 1);
    }

    #[test]
    fn zero_length_operations_never_block_and_change_nothing() {
        let mut pipe = Pipe::<2>::new();
        assert_eq!(pipe.write(&[]), PipeWrite::Wrote(0));
        assert_eq!(pipe.read(&mut []), PipeRead::Read(0));

        pipe.add_writer().unwrap();
        assert_eq!(pipe.read(&mut []), PipeRead::Read(0));
        assert_eq!(pipe.write(&[]), PipeWrite::Wrote(0));

        pipe.add_reader().unwrap();
        assert_eq!(pipe.write(b"ab"), PipeWrite::Wrote(2));
        assert_eq!(pipe.write(&[]), PipeWrite::Wrote(0));
        assert_eq!(pipe.len(), 2);
        assert_eq!(pipe.readers(), 1);
        assert_eq!(pipe.writers(), 1);
        assert_eq!(pipe.read(&mut []), PipeRead::Read(0));
        assert_eq!(pipe.len(), 2);

        let mut closed = Pipe::<2>::new();
        assert_eq!(closed.read(&mut []), PipeRead::Read(0));
        assert_eq!(closed.read(&mut [0u8; 1]), PipeRead::EndOfFile);
    }

    #[test]
    fn end_counts_reject_closing_an_absent_end() {
        let mut pipe = Pipe::<4>::new();
        assert_eq!(pipe.close_reader(), Err(Error::InvalidState));
        assert_eq!(pipe.close_writer(), Err(Error::InvalidState));

        pipe.add_reader().unwrap();
        pipe.add_reader().unwrap();
        assert_eq!(pipe.readers(), 2);
        pipe.close_reader().unwrap();
        pipe.close_reader().unwrap();
        assert_eq!(pipe.close_reader(), Err(Error::InvalidState));
        assert_eq!(pipe.readers(), 0);

        pipe.add_writer().unwrap();
        pipe.close_writer().unwrap();
        assert_eq!(pipe.close_writer(), Err(Error::InvalidState));
        assert_eq!(pipe.writers(), 0);
    }

    #[test]
    fn capacity_one_pipe_alternates_between_full_and_empty() {
        let mut pipe = Pipe::<1>::new();
        assert_eq!(Pipe::<1>::PIPE_BUF, 1);
        assert_eq!(pipe.write(b"a"), PipeWrite::BrokenPipe);
        pipe.add_reader().unwrap();
        pipe.add_writer().unwrap();

        assert_eq!(pipe.write(b"a"), PipeWrite::Wrote(1));
        assert_eq!(pipe.available(), 0);
        assert_eq!(pipe.write(b"b"), PipeWrite::WouldBlock);
        assert_eq!(pipe.write(b"cd"), PipeWrite::WouldBlock);

        let mut out = [0u8; 2];
        assert_eq!(pipe.read(&mut out), PipeRead::Read(1));
        assert_eq!(out[0], b'a');
        assert_eq!(pipe.read(&mut out), PipeRead::WouldBlock);

        // Two bytes exceed PIPE_BUF, so the write is partial rather than atomic.
        assert_eq!(pipe.write(b"cd"), PipeWrite::Wrote(1));
        assert_eq!(pipe.read(&mut out[..1]), PipeRead::Read(1));
        assert_eq!(out[0], b'c');

        for round in 0..300usize {
            let byte = round as u8;
            assert_eq!(pipe.write(&[byte]), PipeWrite::Wrote(1));
            assert_eq!(pipe.read(&mut out[..1]), PipeRead::Read(1));
            assert_eq!(out[0], byte);
        }
        pipe.close_writer().unwrap();
        assert_eq!(pipe.read(&mut out[..1]), PipeRead::EndOfFile);
    }

    /// Replay a deterministic operation mix against a fixed-array model.
    fn compare_with_model<const CAP: usize>(seed: u64, steps: usize) {
        let mut rng = Lcg(seed);
        let mut pipe = Pipe::<CAP>::new();
        let mut model = [0u8; CAP];
        let mut model_len = 0usize;
        let mut readers = 0usize;
        let mut writers = 0usize;
        let mut payload = [0u8; 640];
        let mut out = [0u8; 640];
        let max_len = CAP + 3;

        for step in 0..steps {
            match rng.below(10) {
                0..=3 => {
                    let len = rng.below(max_len + 1);
                    for byte in payload[..len].iter_mut() {
                        *byte = rng.step() as u8;
                    }
                    let expected = if len == 0 {
                        PipeWrite::Wrote(0)
                    } else if readers == 0 {
                        PipeWrite::BrokenPipe
                    } else {
                        let room = CAP - model_len;
                        let count = if len <= Pipe::<CAP>::PIPE_BUF {
                            if len <= room { len } else { 0 }
                        } else {
                            len.min(room)
                        };
                        if count == 0 {
                            PipeWrite::WouldBlock
                        } else {
                            model[model_len..model_len + count].copy_from_slice(&payload[..count]);
                            model_len += count;
                            PipeWrite::Wrote(count)
                        }
                    };
                    assert_eq!(pipe.write(&payload[..len]), expected, "step {step}");
                }
                4..=7 => {
                    let want = rng.below(max_len + 1);
                    let mut expected_bytes = [0u8; 640];
                    let expected = if want == 0 {
                        PipeRead::Read(0)
                    } else if model_len == 0 {
                        if writers == 0 {
                            PipeRead::EndOfFile
                        } else {
                            PipeRead::WouldBlock
                        }
                    } else {
                        let count = want.min(model_len);
                        expected_bytes[..count].copy_from_slice(&model[..count]);
                        model.copy_within(count..model_len, 0);
                        model_len -= count;
                        PipeRead::Read(count)
                    };
                    let got = pipe.read(&mut out[..want]);
                    assert_eq!(got, expected, "step {step}");
                    if let PipeRead::Read(count) = got {
                        assert_eq!(out[..count], expected_bytes[..count], "step {step}");
                    }
                }
                8 => {
                    if rng.below(2) == 0 {
                        pipe.add_reader().unwrap();
                        readers += 1;
                    } else {
                        let expected = if readers == 0 {
                            Err(Error::InvalidState)
                        } else {
                            readers -= 1;
                            Ok(())
                        };
                        assert_eq!(pipe.close_reader(), expected, "step {step}");
                    }
                }
                _ => {
                    if rng.below(2) == 0 {
                        pipe.add_writer().unwrap();
                        writers += 1;
                    } else {
                        let expected = if writers == 0 {
                            Err(Error::InvalidState)
                        } else {
                            writers -= 1;
                            Ok(())
                        };
                        assert_eq!(pipe.close_writer(), expected, "step {step}");
                    }
                }
            }
            assert_eq!(pipe.len(), model_len, "step {step}");
            assert_eq!(pipe.available(), CAP - model_len, "step {step}");
            assert_eq!(pipe.is_empty(), model_len == 0, "step {step}");
            assert_eq!(pipe.readers(), readers, "step {step}");
            assert_eq!(pipe.writers(), writers, "step {step}");
        }
    }

    #[test]
    fn random_operations_match_a_fixed_array_model() {
        compare_with_model::<1>(1, 5_000);
        compare_with_model::<7>(2, 20_000);
        compare_with_model::<16>(3, 20_000);
        compare_with_model::<600>(4, 20_000);
    }
}
