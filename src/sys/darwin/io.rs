//! How the queues of the Apple systems move more than one frame per call: a utun socket hands
//! over and takes many packets as the messages of one `recvmsg_x` or `sendmsg_x`, and a BPF
//! device hands over every frame it holds in one read.

use std::io::{ErrorKind, Result};
#[cfg(target_os = "macos")]
use std::ops::Range;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex, PoisonError};

use xtun_wire::Writes as List;

use super::sys::{msghdr_x, recvmsg_x, sendmsg_x};
use crate::io::{Filled, ReaderStats, WriterStats};
use crate::sys::unix::transport::{Found, IoVecs, Read, Slots, Write, Wrote, retry, wrote};

/// Packets sent with one `sendmsg_x` at most.
const SEND_BATCH: usize = 256;

/// The headers of the messages of one call, each over a run of entries of a scatter list.
#[derive(Default)]
struct Headers(Vec<msghdr_x>);

// SAFETY: the pointers refer to a scatter list that is filled for the call that uses the
// headers; only that call dereferences them, and they are cleared before it returns.
unsafe impl Send for Headers {}
// SAFETY: as above; shared access never dereferences the pointers.
unsafe impl Sync for Headers {}

impl Headers {
    /// Adds a message of `count` entries of the scatter list.
    fn push(&mut self, count: usize) {
        self.0.push(msghdr_x {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: count as libc::c_int,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: 0,
        });
    }

    /// Points every message at its entries of the scatter list of `len` entries at `base`,
    /// which holds the entries of all messages in order and nothing else.
    fn link(&mut self, base: *mut libc::iovec, len: usize) {
        let mut first = 0;
        for header in &mut self.0 {
            header.msg_iov = base.wrapping_add(first);
            first += header.msg_iovlen as usize;
        }
        assert_eq!(first, len, "the messages take up the scatter list");
    }
}

/// The slots of a reader as a scatter list, filled for one call.
#[derive(Default)]
struct Rooms(Vec<libc::iovec>);

// SAFETY: the pointers refer to the slots lent to the call that fills the list; only that
// call dereferences them, and they are cleared before it returns.
unsafe impl Send for Rooms {}
// SAFETY: as above; shared access never dereferences the pointers.
unsafe impl Sync for Rooms {}

/// Reads a utun socket: a packet per message, into a slot each, and every packet that is ready
/// per `recvmsg_x`.
#[derive(Default)]
pub struct MessageReads {
    rooms: Rooms,
    headers: Headers,
}

impl Read for MessageReads {
    fn read(&mut self, fd: RawFd, slots: &mut Slots, frames: usize, stats: &mut ReaderStats, mut frame: impl FnMut(Found<'_>)) -> Filled {
        let MessageReads { rooms: Rooms(rooms), headers } = self;
        rooms.clear();
        headers.0.clear();
        for slot in 0..frames {
            let room = slots.room(slot);
            rooms.push(libc::iovec { iov_base: room.as_mut_ptr().cast(), iov_len: room.len() });
            headers.push(1);
        }
        headers.link(rooms.as_mut_ptr(), rooms.len());
        stats.calls += 1;
        // SAFETY: every message points at a slot of its own, which is writable.
        let result = retry(|| unsafe { recvmsg_x(fd, headers.0.as_ptr(), headers.0.len() as libc::c_uint, libc::MSG_DONTWAIT) });
        let filled = match result {
            Ok(received) => {
                for (slot, header) in headers.0[..received].iter().enumerate() {
                    frame(slots.filled(slot, header.msg_datalen));
                }
                // Fewer packets than slots: the socket is empty.
                if received < frames { Filled::dry() } else { Filled::more() }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => Filled::dry(),
            Err(error) => Filled::failed(error),
        };
        rooms.clear();
        headers.0.clear();
        filled
    }
}

/// Writes a utun socket: a write per message, its pieces gathered, and up to 256 messages per
/// `sendmsg_x`.
///
/// The writers of one socket take turns at the call. The system says of a `sendmsg_x` that
/// meets another on the same socket that it took every message, and now and then delivers
/// none of them.
#[derive(Default)]
pub struct MessageWrites {
    iov: IoVecs,
    headers: Headers,
    /// Held for the length of a call, by whichever writer of the socket makes it.
    turn: Arc<Mutex<()>>,
}

impl Write for MessageWrites {
    fn write(&mut self, fd: RawFd, list: &impl List, stats: &mut WriterStats) -> Result<usize> {
        let MessageWrites { iov, headers, turn } = self;
        let total = list.count();
        let mut next = 0;
        while next < total {
            let chunk = (total - next).min(SEND_BATCH);
            iov.clear();
            headers.0.clear();
            for index in next..next + chunk {
                headers.push(iov.gather(list, index));
            }
            headers.link(iov.as_ptr().cast_mut(), iov.len());
            let sent = {
                let _turn = turn.lock().unwrap_or_else(PoisonError::into_inner);
                send(fd, &headers.0, stats)
            };
            iov.clear();
            headers.0.clear();
            let sent = sent?;
            next += sent;
            if sent < chunk {
                break;
            }
        }
        Ok(next)
    }

    fn try_clone(&self) -> Result<MessageWrites> {
        Ok(MessageWrites { turn: self.turn.clone(), ..MessageWrites::default() })
    }
}

/// Sends the messages in order until the socket has no room. Returns how many it took, those
/// it refused on their own among them.
fn send(fd: RawFd, headers: &[msghdr_x], stats: &mut WriterStats) -> Result<usize> {
    let mut sent = 0;
    while sent < headers.len() {
        let left = &headers[sent..];
        stats.calls += 1;
        // SAFETY: every message points at pieces that the list lends for this call.
        match retry(|| unsafe { sendmsg_x(fd, left.as_ptr(), left.len() as libc::c_uint, libc::MSG_DONTWAIT) }) {
            Ok(0) => break,
            Ok(taken) => {
                sent += taken;
                stats.writes += taken as u64;
            }
            // The call fails for the first message that is left.
            Err(error) => match wrote::<usize>(Err(error), stats)? {
                Wrote::Taken => sent += 1,
                Wrote::Full => break,
            },
        }
    }
    Ok(sent)
}

/// Reads a BPF device: one read takes every frame that came in since the last one, each behind
/// a `bpf_hdr`, at aligned offsets.
#[cfg(target_os = "macos")]
pub struct BpfReads {
    /// As large as the device's buffer, which a read has to offer. The frames of a read lie
    /// here side by side.
    buffer: Box<[u8]>,
    /// The records of the last read that no batch had room for.
    held: Range<usize>,
}

#[cfg(target_os = "macos")]
impl BpfReads {
    pub(super) fn new(fd: RawFd) -> Result<BpfReads> {
        let mut size: libc::c_uint = 0;
        // SAFETY: BIOCGBLEN writes one unsigned int.
        if unsafe { libc::ioctl(fd, super::sys::BIOCGBLEN, &mut size) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(BpfReads { buffer: vec![0u8; size as usize].into_boxed_slice(), held: 0..0 })
    }
}

#[cfg(target_os = "macos")]
impl Read for BpfReads {
    fn slots(&self, _frames: usize) -> usize {
        0
    }

    fn read(&mut self, fd: RawFd, _slots: &mut Slots, frames: usize, stats: &mut ReaderStats, mut frame: impl FnMut(Found<'_>)) -> Filled {
        use super::sys::{BPF_ALIGNMENT, bpf_hdr};
        let buffer = &mut self.buffer[..];
        if self.held.is_empty() {
            stats.calls += 1;
            // SAFETY: `buffer` is writable for its whole length.
            match retry(|| unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) }) {
                Ok(0) => return Filled::dry(),
                Ok(read) => self.held = 0..read,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Filled::dry(),
                Err(error) => return Filled::failed(error),
            }
        }
        let mut handed = 0;
        while handed < frames && self.held.len() >= size_of::<bpf_hdr>() {
            // SAFETY: a record header lies at the start of what is held, inside what was read;
            // it may be unaligned.
            let header = unsafe { std::ptr::read_unaligned(buffer[self.held.start..].as_ptr().cast::<bpf_hdr>()) };
            let (start, len) = (self.held.start + usize::from(header.bh_hdrlen), header.bh_caplen as usize);
            let next = (start + len).next_multiple_of(BPF_ALIGNMENT);
            if start + len > self.held.end || next <= self.held.start {
                stats.malformed += 1;
                self.held = 0..0;
                break;
            }
            self.held.start = next.min(self.held.end);
            if len > 0 && header.bh_caplen == header.bh_datalen {
                frame(Found { bytes: &mut buffer[start..start + len], block: None });
                handed += 1;
            } else {
                stats.malformed += 1;
            }
        }
        if self.held.len() < size_of::<bpf_hdr>() {
            self.held = 0..0;
        }
        // The device may hold more for the next read.
        Filled::more()
    }
}

/// Writes a BPF device a frame per call, its pieces gathered. The device never waits: a frame
/// it cannot take is lost, as on a busy link.
#[cfg(target_os = "macos")]
#[derive(Default)]
pub struct BpfWrites {
    iov: IoVecs,
}

#[cfg(target_os = "macos")]
impl Write for BpfWrites {
    fn write(&mut self, fd: RawFd, list: &impl List, stats: &mut WriterStats) -> Result<usize> {
        for index in 0..list.count() {
            self.iov.clear();
            self.iov.gather(list, index);
            stats.calls += 1;
            // SAFETY: the pointers refer to pieces that `list` lends for this call.
            let result = retry(|| unsafe { libc::writev(fd, self.iov.as_ptr(), self.iov.len() as libc::c_int) });
            self.iov.clear();
            match result {
                Ok(_) => stats.writes += 1,
                Err(error) if matches!(error.raw_os_error(), Some(libc::EBADF | libc::ENXIO)) => return Err(error),
                Err(_) => stats.dropped += 1,
            }
        }
        Ok(list.count())
    }

    fn try_clone(&self) -> Result<BpfWrites> {
        Ok(BpfWrites::default())
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::*;

    /// Writes, each given as its pieces.
    struct Pieces(Vec<Vec<Vec<u8>>>);

    impl List for Pieces {
        fn count(&self) -> usize {
            self.0.len()
        }

        fn pieces<'a>(&'a self, index: usize, mut each: impl FnMut(&'a [u8])) {
            for piece in &self.0[index] {
                each(piece);
            }
        }
    }

    /// Two datagram sockets connected to each other, as a utun socket is to its interface.
    fn pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` holds two descriptors, which are owned right away.
        unsafe {
            assert_eq!(libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()), 0);
            (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))
        }
    }

    fn read(reads: &mut MessageReads, fd: &OwnedFd, slots: &mut Slots, frames: usize, stats: &mut ReaderStats) -> (Vec<Vec<u8>>, Filled) {
        let mut found = Vec::new();
        let filled = reads.read(fd.as_raw_fd(), slots, frames, stats, |raw| {
            assert!(raw.block.is_some(), "a packet lies in a block of its own");
            found.push(raw.bytes.to_vec());
        });
        (found, filled)
    }

    #[test]
    fn messages_cross_a_socket_a_batch_per_call() {
        let (near, far) = pair();
        let family = (libc::AF_INET6 as u32).to_be_bytes().to_vec();
        let list = Pieces((0..5u8).map(|number| vec![family.clone(), vec![0x60, number], vec![number; 40 + usize::from(number)]]).collect());
        let mut writer = WriterStats::default();
        assert_eq!(MessageWrites::default().write(near.as_raw_fd(), &list, &mut writer).unwrap(), 5);
        assert_eq!((writer.writes, writer.dropped), (5, 0));
        assert!(writer.calls <= 5, "one call takes many messages");

        let mut reads = MessageReads::default();
        let mut slots = Slots::new(8);
        let mut reader = ReaderStats::default();
        // A batch of two slots is filled and says that the socket may hold more.
        let (found, filled) = read(&mut reads, &far, &mut slots, 2, &mut reader);
        assert_eq!(found, [list.0[0].concat(), list.0[1].concat()], "the address family stays in front of its packet");
        assert!(!filled.dry && filled.error.is_none());
        // A batch with slots left over says that the socket is empty.
        let (found, filled) = read(&mut reads, &far, &mut slots, 8, &mut reader);
        assert_eq!(found, [list.0[2].concat(), list.0[3].concat(), list.0[4].concat()]);
        assert!(filled.dry && filled.error.is_none());
        let (found, filled) = read(&mut reads, &far, &mut slots, 8, &mut reader);
        assert!(found.is_empty() && filled.dry && filled.error.is_none());
        assert_eq!(reader.calls, 3);
    }

    #[test]
    fn the_writers_of_a_socket_take_turns() {
        let (near, far) = pair();
        let first = MessageWrites::default();
        let mut second = first.try_clone().unwrap();
        // Messages on the other socket, without waiting for one.
        let waiting = || {
            let mut message = [0u8; 64];
            // SAFETY: `message` is writable for its length.
            unsafe { libc::recv(far.as_raw_fd(), message.as_mut_ptr().cast(), message.len(), libc::MSG_DONTWAIT) }
        };
        // While one writer is at its call, the other waits for its turn.
        let turn = first.turn.lock().unwrap();
        std::thread::scope(|scope| {
            let writing = scope.spawn(|| {
                let list = Pieces(vec![vec![vec![0x45; 20]]]);
                second.write(near.as_raw_fd(), &list, &mut WriterStats::default()).unwrap()
            });
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert!(waiting() < 0, "nothing is written out of turn");
            drop(turn);
            assert_eq!(writing.join().unwrap(), 1);
        });
        assert_eq!(waiting(), 20);
        // A writer of another socket has turns of its own.
        assert!(first.turn.try_lock().is_ok());
        assert!(MessageWrites::default().turn.try_lock().is_ok());
    }

    #[test]
    fn a_descriptor_that_is_not_open_fails_a_write_and_a_read() {
        let list = Pieces(vec![vec![vec![0x45; 20]]]);
        let error = MessageWrites::default().write(-1, &list, &mut WriterStats::default()).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        let filled = MessageReads::default().read(-1, &mut Slots::new(1), 1, &mut ReaderStats::default(), |_| panic!("nothing was read"));
        assert_eq!(filled.error.and_then(|error| error.raw_os_error()), Some(libc::EBADF));
    }

    /// A record as BPF lays it out: the header, the frame, and padding to the alignment.
    #[cfg(target_os = "macos")]
    fn record(frame: &[u8], original: usize) -> Vec<u8> {
        const HEADER: usize = 18;
        let mut record = vec![0u8; HEADER];
        record[8..12].copy_from_slice(&(frame.len() as u32).to_ne_bytes());
        record[12..16].copy_from_slice(&(original as u32).to_ne_bytes());
        record[16..18].copy_from_slice(&(HEADER as u16).to_ne_bytes());
        record.extend_from_slice(frame);
        record.resize(record.len().next_multiple_of(super::super::sys::BPF_ALIGNMENT), 0);
        record
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_records_of_a_bpf_read_are_handed_out_a_batch_at_a_time() {
        let frames: Vec<Vec<u8>> = (0..3u8).map(|number| vec![number; 60 + 2 * usize::from(number)]).collect();
        // The second record was cut short by the device, and the last one ends with the read,
        // without its padding.
        let mut buffer: Vec<u8> = [record(&frames[0], 60), record(&frames[1][..20], 62), record(&frames[2], 64)].concat();
        buffer.truncate(buffer.len() - 2);
        let held = 0..buffer.len();
        let mut reads = BpfReads { buffer: buffer.into_boxed_slice(), held };
        let (mut slots, mut stats) = (Slots::new(0), ReaderStats::default());
        // No descriptor is read while records of the last read are held.
        let mut found = Vec::new();
        let mut keep = |raw: Found<'_>| {
            assert!(raw.block.is_none(), "the frames of a read lie side by side");
            found.push(raw.bytes.to_vec());
        };
        let filled = reads.read(-1, &mut slots, 1, &mut stats, &mut keep);
        assert!(!filled.dry && filled.error.is_none());
        let filled = reads.read(-1, &mut slots, 4, &mut stats, &mut keep);
        assert_eq!(found, [frames[0].clone(), frames[2].clone()]);
        assert!(!filled.dry && filled.error.is_none());
        assert_eq!((stats.malformed, stats.calls), (1, 0));
        assert!(reads.held.is_empty());
        let filled = reads.read(-1, &mut slots, 4, &mut stats, |_| panic!("nothing was read"));
        assert_eq!(filled.error.and_then(|error| error.raw_os_error()), Some(libc::EBADF));
        assert_eq!(stats.calls, 1);
    }
}
