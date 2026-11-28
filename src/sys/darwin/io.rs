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
#[cfg(target_os = "macos")]
use crate::block::Memory;
use crate::io::{Filled, ReaderStats, WriterStats};
#[cfg(target_os = "macos")]
use crate::sys::unix::transport::SLOT;
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
/// per `recvmsg_x`, or per as many calls as the batch takes.
pub struct MessageReads {
    rooms: Rooms,
    headers: Headers,
    /// The most messages one call takes: the system cuts a call for more down to
    /// `kern.ipc.maxrecvmsgx`.
    most: usize,
}

impl MessageReads {
    pub(super) fn new() -> Result<MessageReads> {
        let mut most: libc::c_uint = 0;
        let mut length = size_of::<libc::c_uint>();
        // SAFETY: the name is NUL-terminated, `most` is writable for `length` bytes, and nothing
        // is written to the system.
        let read = unsafe {
            libc::sysctlbyname(c"kern.ipc.maxrecvmsgx".as_ptr(), (&raw mut most).cast(), &mut length, std::ptr::null_mut(), 0)
        };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            return Err(std::io::Error::new(error.kind(), format!("reading kern.ipc.maxrecvmsgx: {error}")));
        }
        Ok(MessageReads { rooms: Rooms::default(), headers: Headers::default(), most: (most as usize).max(1) })
    }
}

impl Read for MessageReads {
    fn read(&mut self, fd: RawFd, slots: &mut Slots, frames: usize, stats: &mut ReaderStats, mut frame: impl FnMut(Found<'_>)) -> Filled {
        let MessageReads { rooms: Rooms(rooms), headers, most } = self;
        let mut first = 0;
        let filled = loop {
            let asked = (frames - first).min(*most);
            rooms.clear();
            headers.0.clear();
            for slot in first..first + asked {
                let room = slots.room(slot);
                rooms.push(libc::iovec { iov_base: room.as_mut_ptr().cast(), iov_len: room.len() });
                headers.push(1);
            }
            headers.link(rooms.as_mut_ptr(), rooms.len());
            stats.calls += 1;
            // SAFETY: every message points at a slot of its own, which is writable.
            let result = retry(|| unsafe { recvmsg_x(fd, headers.0.as_ptr(), headers.0.len() as libc::c_uint, libc::MSG_DONTWAIT) });
            match result {
                Ok(received) => {
                    for (index, header) in headers.0[..received].iter().enumerate() {
                        frame(slots.filled(first + index, header.msg_datalen));
                    }
                    first += received;
                    // Fewer packets than the call asked for: the socket is empty.
                    if received < asked {
                        break Filled::dry();
                    }
                    if first == frames {
                        break Filled::more();
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break Filled::dry(),
                Err(error) => break Filled::failed(error),
            }
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
            iov.clear();
            headers.0.clear();
            // Up to the first empty write: the system says of a call with an empty message that
            // it took the messages before it, and sends none of them.
            for index in next..total.min(next + SEND_BATCH) {
                let pieces = iov.gather(list, index);
                if pieces == 0 {
                    break;
                }
                headers.push(pieces);
            }
            let chunk = headers.0.len();
            if chunk == 0 {
                // An empty write goes nowhere.
                stats.dropped += 1;
                next += 1;
                continue;
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
    /// here side by side, each lent as a stretch of its own.
    buffer: Memory,
    /// The records of the last read that no batch had room for.
    held: Range<usize>,
    /// Whether the last read took everything the device had. Once its records are handed out,
    /// the device is known to be empty without a read that finds nothing.
    emptied: bool,
}

#[cfg(target_os = "macos")]
impl BpfReads {
    pub(super) fn new(fd: RawFd) -> Result<BpfReads> {
        let mut size: libc::c_uint = 0;
        // SAFETY: BIOCGBLEN writes one unsigned int.
        if unsafe { libc::ioctl(fd, super::sys::BIOCGBLEN, &mut size) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(BpfReads { buffer: Memory::new(size as usize), held: 0..0, emptied: false })
    }
}

#[cfg(target_os = "macos")]
impl Read for BpfReads {
    fn slots(&self, _frames: usize) -> usize {
        0
    }

    fn read(&mut self, fd: RawFd, _slots: &mut Slots, frames: usize, stats: &mut ReaderStats, mut frame: impl FnMut(Found<'_>)) -> Filled {
        use super::sys::{BPF_ALIGNMENT, bpf_hdr};
        let (base, size) = (self.buffer.start().as_ptr(), self.buffer.len());
        if self.held.is_empty() {
            stats.calls += 1;
            // SAFETY: the buffer is writable for its whole length, and no frame of it is lent.
            match retry(|| unsafe { libc::read(fd, base.cast(), size) }) {
                Ok(0) => return Filled::dry(),
                Ok(read) => {
                    self.held = 0..read;
                    // The device sets a buffer aside for the reader once a record no longer fits
                    // behind the others, and keeps what comes after that in a second one. Records
                    // that leave room for one more at its largest are all the device had.
                    self.emptied = read + SLOT <= size;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Filled::dry(),
                Err(error) => return Filled::failed(error),
            }
        }
        let mut handed = 0;
        while handed < frames && self.held.len() >= size_of::<bpf_hdr>() {
            // SAFETY: a record header lies at the start of what is held, inside what was read;
            // it may be unaligned.
            let header = unsafe { std::ptr::read_unaligned(base.add(self.held.start).cast::<bpf_hdr>()) };
            let (start, len) = (self.held.start + usize::from(header.bh_hdrlen), header.bh_caplen as usize);
            let next = (start + len).next_multiple_of(BPF_ALIGNMENT);
            if start + len > self.held.end || next <= self.held.start {
                stats.malformed += 1;
                self.held = 0..0;
                break;
            }
            self.held.start = next.min(self.held.end);
            if len > 0 && header.bh_caplen == header.bh_datalen {
                // SAFETY: the frame lies inside what was read, apart from every other frame.
                let bytes = unsafe { std::slice::from_raw_parts_mut(base.add(start), len) };
                frame(Found { bytes, block: None });
                handed += 1;
            } else {
                stats.malformed += 1;
            }
        }
        if self.held.len() < size_of::<bpf_hdr>() {
            self.held = 0..0;
        }
        if self.held.is_empty() && self.emptied {
            return Filled::dry();
        }
        // Records are left for the next batch, or the device may hold a second buffer.
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
            if self.iov.gather(list, index) == 0 {
                // An empty write goes nowhere: the device refuses it.
                stats.dropped += 1;
                continue;
            }
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

        let mut reads = MessageReads::new().unwrap();
        let mut slots = Slots::new(8).unwrap();
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

    /// The system takes no more messages per call than `kern.ipc.maxrecvmsgx`: a batch of more
    /// slots is read with as many calls as it takes, and the socket is empty only once a call
    /// finds fewer messages than it asked for.
    #[test]
    fn a_batch_larger_than_one_call_takes_is_read_whole() {
        let (near, far) = pair();
        for fd in [&near, &far] {
            for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
                let size: libc::c_int = 1 << 20;
                // SAFETY: the option reads one int.
                let set = unsafe { libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, option, (&raw const size).cast(), 4) };
                assert_eq!(set, 0);
            }
        }
        let reads = MessageReads::new().unwrap();
        let count = reads.most + 44;
        let list = Pieces((0..count).map(|number| vec![(number as u32).to_be_bytes().to_vec()]).collect());
        assert_eq!(MessageWrites::default().write(near.as_raw_fd(), &list, &mut WriterStats::default()).unwrap(), count);
        let (mut reads, mut slots, mut stats) = (reads, Slots::new(count).unwrap(), ReaderStats::default());
        let (found, filled) = read(&mut reads, &far, &mut slots, count, &mut stats);
        assert_eq!(found.len(), count);
        assert_eq!(found[count - 1], ((count - 1) as u32).to_be_bytes());
        assert!(!filled.dry && filled.error.is_none(), "a batch that was filled says that the socket may hold more");
        assert_eq!(stats.calls, 2);
    }

    /// The system says of a `sendmsg_x` with an empty message that it took the messages before
    /// it, and sends none of them: an empty write goes on its own, and nowhere.
    #[test]
    fn an_empty_write_loses_none_of_the_writes_around_it() {
        let (near, far) = pair();
        let list = Pieces(vec![vec![vec![1; 20]], vec![vec![2; 20]], vec![], vec![vec![4; 20]], vec![]]);
        let mut stats = WriterStats::default();
        assert_eq!(MessageWrites::default().write(near.as_raw_fd(), &list, &mut stats).unwrap(), 5);
        assert_eq!((stats.writes, stats.dropped), (3, 2));
        let mut reads = MessageReads::new().unwrap();
        let (found, _) = read(&mut reads, &far, &mut Slots::new(8).unwrap(), 8, &mut ReaderStats::default());
        assert_eq!(found, [vec![1; 20], vec![2; 20], vec![4; 20]]);
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
        let filled = MessageReads::new().unwrap().read(-1, &mut Slots::new(1).unwrap(), 1, &mut ReaderStats::default(), |_| panic!("nothing was read"));
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

    /// A reader of a BPF device that holds `bytes`, as if a read had just put them there.
    #[cfg(target_os = "macos")]
    fn holding(bytes: &[u8]) -> BpfReads {
        let buffer = Memory::new(bytes.len());
        // SAFETY: the memory is new and as long as the bytes.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.start().as_ptr(), bytes.len()) };
        BpfReads { buffer, held: 0..bytes.len(), emptied: false }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_records_of_a_bpf_read_are_handed_out_a_batch_at_a_time() {
        let frames: Vec<Vec<u8>> = (0..3u8).map(|number| vec![number; 60 + 2 * usize::from(number)]).collect();
        // The second record was cut short by the device, and the last one ends with the read,
        // without its padding.
        let mut buffer: Vec<u8> = [record(&frames[0], 60), record(&frames[1][..20], 62), record(&frames[2], 64)].concat();
        buffer.truncate(buffer.len() - 2);
        let mut reads = holding(&buffer);
        let (mut slots, mut stats) = (Slots::new(0).unwrap(), ReaderStats::default());
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

    /// The frames of one read are lent together, and stay lent while the reader moves.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_frames_of_a_bpf_read_stay_valid_together_and_where_the_reader_moves() {
        let frames: Vec<Vec<u8>> = (0..3u8).map(|number| vec![number; 60 + usize::from(number)]).collect();
        let bytes: Vec<u8> = frames.iter().flat_map(|frame| record(frame, frame.len())).collect();
        let mut reads = holding(&bytes);
        let (mut slots, mut stats) = (Slots::new(0).unwrap(), ReaderStats::default());
        let mut lent = Vec::new();
        reads.read(-1, &mut slots, 4, &mut stats, |found| lent.push((found.bytes.as_mut_ptr(), found.bytes.len())));
        let reads = std::hint::black_box(reads);
        for ((data, len), frame) in lent.iter().zip(&frames) {
            // SAFETY: the reader has not read again since it lent the frames.
            let bytes = unsafe { std::slice::from_raw_parts_mut(*data, *len) };
            bytes[0] ^= 0xff;
            bytes[0] ^= 0xff;
            assert_eq!(bytes, &frame[..]);
        }
        drop(reads);
    }

    /// What a reader of a BPF device hands out of `fd` in one batch of up to `frames` frames.
    #[cfg(target_os = "macos")]
    fn batch(reads: &mut BpfReads, fd: &OwnedFd, frames: usize, stats: &mut ReaderStats) -> (Vec<Vec<u8>>, Filled) {
        let mut found = Vec::new();
        let filled = reads.read(fd.as_raw_fd(), &mut Slots::new(0).unwrap(), frames, stats, |raw| found.push(raw.bytes.to_vec()));
        (found, filled)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_bpf_read_that_leaves_room_for_a_record_finds_the_device_empty() {
        let (near, far) = pair();
        crate::sys::unix::set_nonblocking(far.as_raw_fd()).unwrap();
        let frames: Vec<Vec<u8>> = (0..3u8).map(|number| vec![number; 60]).collect();
        let records: Vec<u8> = frames.iter().flat_map(|frame| record(frame, frame.len())).collect();
        let send = || {
            // SAFETY: `records` is readable for its length.
            assert_eq!(unsafe { libc::write(near.as_raw_fd(), records.as_ptr().cast(), records.len()) }, records.len() as isize);
        };
        let mut stats = ReaderStats::default();

        // Room for one more record: the device is empty, which the reader says with the last
        // record it hands out.
        let mut reads = BpfReads { buffer: Memory::new(records.len() + SLOT), held: 0..0, emptied: false };
        send();
        let (first, filled) = batch(&mut reads, &far, 2, &mut stats);
        assert!(!filled.dry && filled.error.is_none(), "a record is left for the next batch");
        let (second, filled) = batch(&mut reads, &far, 2, &mut stats);
        assert!(filled.dry && filled.error.is_none());
        assert_eq!([first, second].concat(), frames);
        assert_eq!(stats.calls, 1);

        // A byte less: the device may hold a second buffer, and a read finds out.
        let mut reads = BpfReads { buffer: Memory::new(records.len() + SLOT - 1), held: 0..0, emptied: false };
        send();
        let (all, filled) = batch(&mut reads, &far, 4, &mut stats);
        assert!(!filled.dry && filled.error.is_none());
        assert_eq!(all, frames);
        let (none, filled) = batch(&mut reads, &far, 4, &mut stats);
        assert!(none.is_empty() && filled.dry && filled.error.is_none());
        assert_eq!(stats.calls, 3);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_write_without_pieces_to_a_bpf_device_is_dropped_without_a_call() {
        let (near, far) = pair();
        let list = Pieces(vec![vec![], vec![vec![0xaa; 14], vec![0xbb; 46]], vec![]]);
        let mut stats = WriterStats::default();
        assert_eq!(BpfWrites::default().write(near.as_raw_fd(), &list, &mut stats).unwrap(), 3);
        assert_eq!((stats.writes, stats.dropped, stats.calls), (1, 2, 1));
        let mut frame = [0u8; 64];
        // SAFETY: `frame` is writable for its length.
        let read = unsafe { libc::recv(far.as_raw_fd(), frame.as_mut_ptr().cast(), frame.len(), libc::MSG_DONTWAIT) };
        assert_eq!(read, 60);
        assert_eq!(frame[..60], [[0xaa; 14].as_slice(), [0xbb; 46].as_slice()].concat());
    }
}
