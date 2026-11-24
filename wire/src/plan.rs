//! Planning the writes of a batch of packets, by one rule: what the device can carry goes to the
//! device as it is, what it cannot carry is carried out here, and what can be joined is joined.
//!
//! Consecutive packets of one TCP or UDP flow become one segment of up to 64 KiB with a single
//! copy of the headers in front, where the device takes segments: the system takes it in one
//! write and its TCP stack handles it as one packet. The rules are those of Linux's own receive
//! offload, so a segment that the system cuts again gives back exactly the packets that went in.
//! A segment or a partial checksum that the device cannot be told about is cut and completed
//! before it is written.
//!
//! Nothing is copied but headers. A plan lists, for every write, a few bytes of scratch (the
//! device's prefix and, where headers were made anew, those headers) and the packets whose bytes
//! follow it. A packet may come in pieces, its headers in the first and its payload in the
//! others: the pieces go to the device as they lie.

use std::io;

use crate::cut::{Cut, MAX_HEADER, complete_into, segment_header_len_head};
use crate::framing::{Framing, Prefix};
use crate::packet::{
    ACK, Checksum, Gso, GsoKind, Head, PSH, Packet, Parts, Transport, each_in, first_byte, invalid, ipv4_header_checksum, link_len_head,
    pseudo, write_u16,
};
use crate::tunhdr;
use crate::vnet::{self, Header};

/// No member after this one, and no end before the packet's own.
const END: u32 = u32::MAX;
/// One `writev` takes at most `UIO_MAXIOV` pieces: the scratch and those of the members.
const MAX_PIECES: usize = 1024;
/// The kernel turns a TCP segment size below this into this.
const MIN_TCP_SEGMENT: usize = 8;

/// What a device takes.
#[derive(Clone, Copy, Debug)]
pub struct Takes {
    /// How its frames are laid out.
    pub framing: Framing,
    /// Whether it takes TCP segments of up to 64 KiB.
    pub tcp: bool,
    /// Whether it takes UDP segments, which on Linux needs `TUN_F_USO4` and `TUN_F_USO6`.
    pub udp: bool,
    /// How many datagrams a UDP segment may stand for: Linux's `UDP_MAX_SEGMENTS`.
    pub udp_max_segments: usize,
    /// The longest frame that is not a segment, without the prefix.
    pub max_frame: usize,
}

impl Takes {
    /// Whether the device can be told what a packet leaves to it: a segment to cut or a
    /// checksum to complete.
    fn carries(&self, head: Head<'_>, checksum: Checksum, gso: Option<Gso>) -> bool {
        match self.framing.prefix {
            Prefix::None | Prefix::Family(_) => false,
            Prefix::Virtio(_) => match gso.map(|gso| gso.kind) {
                None => true,
                Some(GsoKind::Tcp4 { .. } | GsoKind::Tcp6 { .. }) => self.tcp,
                Some(GsoKind::Udp) => self.udp,
            },
            Prefix::TunHdr { .. } => tunhdr::describes(head, checksum, gso, self.framing.ethernet),
        }
    }
}

/// Writes in order, each made of pieces that go out together as one frame.
pub trait Writes {
    /// How many writes there are.
    fn count(&self) -> usize;

    /// Hands `each` the pieces of write `index` in order. No piece is empty.
    fn pieces<'a>(&'a self, index: usize, each: impl FnMut(&'a [u8]));
}

/// The plan for writing one batch.
#[derive(Default)]
pub struct Plan {
    table: FlowTable,
    writes: Vec<Write>,
    next: Vec<u32>,
    scratch: Vec<u8>,
}

/// One write: its scratch, then each member's bytes from `skip` on.
#[derive(Clone, Copy, Debug)]
struct Write {
    first: u32,
    last: u32,
    count: u32,
    /// How many pieces the members come in, at most.
    pieces: u32,
    skip: u32,
    /// Where the bytes of the only member end, or [`END`] for all of every member.
    end: u32,
    scratch: (u32, u32),
    kind: Kind,
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    /// Written as it is, behind the prefix that this header makes.
    Raw(Header),
    /// A run of one flow that gets new headers.
    Joined(Run),
    /// A packet cut or completed here: its headers are in the scratch already.
    Piece,
}

#[derive(Clone, Copy, Debug)]
struct Run {
    info: Transport,
    segment_size: usize,
    payload: usize,
    next_seq: u32,
    open: bool,
    psh: bool,
    /// The only member already carries a partial checksum and needs no new headers.
    partial: bool,
}

impl Plan {
    /// A plan without writes.
    pub fn new() -> Plan {
        Plan::default()
    }

    /// Plans the writes of `packets` for a device that takes what `takes` says. Packets of one
    /// flow stay in their order. Fails, without planning anything, when a packet is marked as a
    /// segment that cannot be cut as marked, has its checksum field outside itself, makes a
    /// frame longer than the device takes, or comes in more than 1023 pieces.
    pub fn plan(&mut self, takes: &Takes, packets: &[Packet<'_>]) -> io::Result<()> {
        self.plan_parts(takes, packets)
    }

    /// [`Plan::plan`] for packets of either kind: [`Packet`]s, or [`Pieces`] with pieces of any
    /// type.
    ///
    /// [`Pieces`]: crate::Pieces
    pub fn plan_parts<P: Parts>(&mut self, takes: &Takes, packets: &[P]) -> io::Result<()> {
        self.writes.clear();
        self.scratch.clear();
        self.next.clear();
        self.next.resize(packets.len(), END);
        let joins = takes.tcp || takes.udp;
        if joins {
            self.table.reset(packets.len());
        }
        for (index, packet) in packets.iter().enumerate() {
            if let Err(error) = self.add(takes, joins, index as u32, packet, packets) {
                self.writes.clear();
                return Err(error);
            }
        }
        self.finish(takes, packets);
        Ok(())
    }

    /// The planned writes of `packets`, the batch that was planned.
    pub fn writes<'a, P: Parts>(&'a self, packets: &'a [P]) -> Planned<'a, P> {
        Planned { plan: self, packets }
    }

    fn add<P: Parts>(&mut self, takes: &Takes, joins: bool, index: u32, packet: &P, packets: &[P]) -> io::Result<()> {
        let whole = Head::of(packet);
        // Where the head does not say everything about a packet, its headers may go on past
        // the head: they are read again from a copy of the packet's first bytes.
        if packet.pieces() == 0 || whole.bytes.len() >= whole.len.min(MAX_HEADER) {
            return self.add_read(takes, joins, index, packet, packets, whole, false).map(drop);
        }
        if self.add_read(takes, joins, index, packet, packets, whole, true)? {
            return Ok(());
        }
        let (bytes, len) = first_bytes(packet);
        self.add_read(takes, joins, index, packet, packets, Head { bytes: &bytes[..len], len: whole.len }, false).map(drop)
    }

    /// Plans `packet` by what `head`, its first bytes, says about it. With `again`, a packet
    /// about which `head` does not say everything is left alone, and the answer is `false`.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn add_read<P: Parts>(
        &mut self,
        takes: &Takes,
        joins: bool,
        index: u32,
        packet: &P,
        packets: &[P],
        head: Head<'_>,
        again: bool,
    ) -> io::Result<bool> {
        let (data, checksum) = (head.bytes, packet.checksum());
        // The head and the pieces behind it, next to the scratch of a write.
        let pieces = 1 + packet.pieces();
        if 1 + pieces > MAX_PIECES {
            return Err(too_many());
        }
        let pieces = pieces as u32;
        let link = if takes.framing.ethernet { link_len_head(head) } else { Some(0) };
        let gso = match (packet.gso(), link) {
            (Some(gso), Some(link)) => match segment_header_len_head(head, link, checksum, gso) {
                Ok(header_len) => Some(Gso { header_len, ..gso }),
                Err(_) if again => return Ok(false),
                Err(error) => return Err(error),
            },
            (Some(_), None) if again => return Ok(false),
            (Some(_), None) => return Err(invalid("a segment has to carry IPv4 or IPv6")),
            (None, _) => {
                if let Checksum::Partial { start, offset } = checksum
                    && usize::from(start) + usize::from(offset) + 2 > head.len
                {
                    return Err(invalid("the checksum field lies outside the packet"));
                }
                None
            }
        };
        // The flow, so that its packets stay in order whatever becomes of each.
        let info = if joins { link.and_then(|link| Transport::read_head(head, link)) } else { None };
        let claims = gso.is_some() || matches!(checksum, Checksum::Partial { .. });
        let carried = !claims || takes.carries(head, checksum, gso);
        if again && (link.is_none() || (joins && info.is_none()) || !carried) {
            return Ok(false);
        }
        let key = info.as_ref().map(|info| Key::new(data, info));
        if !carried {
            let first = self.writes.len() as u32;
            self.carry_out(takes, index, packet, head, link.unwrap_or(0), gso)?;
            if let Some(key) = key {
                self.table.set(key, first);
            }
            return Ok(true);
        }
        if let Some(gso) = gso {
            self.push_raw(index, pieces, Header::for_packet(checksum, Some(gso)), key);
            return Ok(true);
        }
        if head.len > takes.max_frame {
            return Err(too_long(takes.max_frame));
        }
        let (Some(info), Some(key)) = (info, key) else {
            self.push_raw(index, pieces, Header::for_packet(checksum, None), None);
            return Ok(true);
        };
        // A run takes its headers from the head of its first packet.
        if info.header_len > packet.head().len() {
            self.push_raw(index, pieces, Header::for_packet(checksum, None), Some(key));
            return Ok(true);
        }
        let trusted = match checksum {
            Checksum::Partial { start, offset } => {
                usize::from(start) == info.transport && usize::from(offset) == info.checksum_offset()
            }
            Checksum::Valid => true,
            Checksum::Unverified => info.verify_parts(packet, head.len),
        };
        if !trusted {
            self.push_raw(index, pieces, Header::for_packet(checksum, None), Some(key));
            return Ok(true);
        }
        let candidate = Candidate::new(head, &info, takes, pieces);
        if let Some(write) = self.table.get(&key)
            && self.can_join(takes, write, &candidate, data, packets)
        {
            self.join(write, index, &candidate);
            return Ok(true);
        }
        let open = candidate.joinable && !candidate.psh && (!info.tcp || candidate.payload >= MIN_TCP_SEGMENT);
        let run = Run {
            info,
            segment_size: candidate.payload,
            payload: candidate.payload,
            next_seq: candidate.seq.wrapping_add(candidate.payload as u32),
            open,
            psh: candidate.psh,
            partial: matches!(checksum, Checksum::Partial { .. }),
        };
        let write = self.writes.len() as u32;
        self.writes.push(Write { first: index, last: index, count: 1, pieces, skip: 0, end: END, scratch: (0, 0), kind: Kind::Joined(run) });
        self.table.set(key, write);
        Ok(true)
    }

    fn push_raw(&mut self, index: u32, pieces: u32, header: Header, key: Option<Key>) {
        let write = self.writes.len() as u32;
        self.writes.push(Write { first: index, last: index, count: 1, pieces, skip: 0, end: END, scratch: (0, 0), kind: Kind::Raw(header) });
        if let Some(key) = key {
            self.table.set(key, write);
        }
    }

    /// Does here what `packet` leaves to a device that cannot be told: cuts a segment into its
    /// packets and completes checksums. Each packet becomes a write of its own, its headers in
    /// the scratch behind a prefix that leaves nothing to the device.
    fn carry_out<P: Parts>(&mut self, takes: &Takes, index: u32, packet: &P, head: Head<'_>, link: usize, gso: Option<Gso>) -> io::Result<()> {
        let prefix = takes.framing.prefix;
        // Only a tun device takes the address family, and its packets start with the IP version.
        let v6 = first_byte(packet).is_some_and(|byte| byte >> 4 == 6);
        let pieces = 1 + packet.pieces() as u32;
        let Plan { writes, scratch, .. } = self;
        let lead = |scratch: &mut Vec<u8>| {
            let at = scratch.len();
            scratch.resize(at + prefix.len(), 0);
            prefix.write(&Header::default(), v6, &mut scratch[at..]);
            at
        };
        let mut piece = |scratch: &Vec<u8>, at: usize, body: std::ops::Range<usize>| {
            if scratch.len() - at - prefix.len() + body.len() > takes.max_frame {
                return Err(too_long(takes.max_frame));
            }
            let scratch = (at as u32, scratch.len() as u32);
            let (skip, end) = (body.start as u32, body.end as u32);
            writes.push(Write { first: index, last: index, count: 1, pieces, skip, end, scratch, kind: Kind::Piece });
            Ok(())
        };
        match (gso, packet.checksum()) {
            (Some(gso), checksum) => {
                let cut = Cut::of(head, link, checksum, gso);
                for cut_packet in 0..cut.count {
                    let at = lead(scratch);
                    let body = cut.copy_header(cut_packet, packet, scratch);
                    piece(scratch, at, body)?;
                }
                Ok(())
            }
            (None, Checksum::Partial { start, offset }) => {
                let at = lead(scratch);
                let body = complete_into(packet, head.len, usize::from(start), usize::from(offset), scratch);
                piece(scratch, at, body)
            }
            (None, _) => unreachable!("only a packet that leaves something to the device is carried out"),
        }
    }

    fn can_join<P: Parts>(&self, takes: &Takes, write: u32, candidate: &Candidate, data: &[u8], packets: &[P]) -> bool {
        let write = &self.writes[write as usize];
        let Kind::Joined(run) = &write.kind else {
            return false;
        };
        let info = &run.info;
        if !run.open || !candidate.joinable || candidate.header_len != info.header_len || candidate.payload > run.segment_size {
            return false;
        }
        let total = info.header_len + run.payload + candidate.payload;
        let limit = info.link + if info.v6 { 65_535 + 40 } else { 65_535 };
        let members = if info.tcp { usize::MAX } else { takes.udp_max_segments };
        if total > limit || write.count as usize >= members || 1 + (write.pieces + candidate.pieces) as usize > MAX_PIECES {
            return false;
        }
        let first = packets[write.first as usize].head();
        let ip = info.link;
        let same_ip = if info.v6 {
            first[ip..ip + 4] == data[ip..ip + 4] && first[ip + 7] == data[ip + 7]
        } else {
            first[ip + 1] == data[ip + 1] && first[ip + 6] & 0xe0 == data[ip + 6] & 0xe0 && first[ip + 8] == data[ip + 8]
        };
        // The link layer headers, addresses and tags, must match as well.
        if !same_ip || first[..ip] != data[..ip] {
            return false;
        }
        if info.tcp {
            let t = info.transport;
            // Everything after the sequence number must match except PSH: acknowledgement, header
            // length, flags, window and options.
            let same_tcp = first[t + 8..t + 13] == data[t + 8..t + 13]
                && first[t + 14..t + 16] == data[t + 14..t + 16]
                && first[t + 20..info.header_len] == data[t + 20..info.header_len];
            if !same_tcp || candidate.seq != run.next_seq {
                return false;
            }
        }
        true
    }

    fn join(&mut self, write: u32, index: u32, candidate: &Candidate) {
        let last = self.writes[write as usize].last;
        self.next[last as usize] = index;
        let write = &mut self.writes[write as usize];
        write.last = index;
        write.count += 1;
        write.pieces += candidate.pieces;
        if let Kind::Joined(run) = &mut write.kind {
            run.payload += candidate.payload;
            run.next_seq = run.next_seq.wrapping_add(candidate.payload as u32);
            run.partial = false;
            if candidate.payload < run.segment_size || candidate.psh {
                run.open = false;
            }
            run.psh |= candidate.psh;
        }
    }

    /// Writes the scratch of every write that has none yet: the prefix and, for a run, its new
    /// headers.
    fn finish<P: Parts>(&mut self, takes: &Takes, packets: &[P]) {
        let prefix = takes.framing.prefix;
        let prefix_len = prefix.len();
        let Plan { writes, scratch, .. } = self;
        for write in writes.iter_mut() {
            let packet = &packets[write.first as usize];
            let first = packet.head();
            let at = scratch.len();
            let (header, v6) = match write.kind {
                Kind::Piece => continue,
                Kind::Joined(run) if run.partial => {
                    let info = &run.info;
                    let checksum = Checksum::Partial { start: info.transport as u16, offset: info.checksum_offset() as u16 };
                    (Header::for_packet(checksum, None), info.v6)
                }
                // Only a tun device takes the address family, and its packets start with the IP
                // version.
                Kind::Raw(header) => (header, first_byte(packet).is_some_and(|byte| byte >> 4 == 6)),
                Kind::Joined(run) => {
                    let info = &run.info;
                    scratch.resize(at + prefix_len + info.header_len, 0);
                    let (lead, header) = scratch[at..].split_at_mut(prefix_len);
                    header.copy_from_slice(&first[..info.header_len]);
                    let (ip, t) = (info.link, info.transport);
                    if info.v6 {
                        write_u16(header, ip + 4, (info.header_len - ip - 40 + run.payload) as u16);
                    } else {
                        write_u16(header, ip + 2, (info.header_len - ip + run.payload) as u16);
                        ipv4_header_checksum(&mut header[ip..t]);
                    }
                    let transport_len = info.header_len - t + run.payload;
                    if info.tcp {
                        if run.psh {
                            header[t + 13] |= PSH;
                        }
                    } else {
                        write_u16(header, t + 4, transport_len as u16);
                    }
                    let partial = pseudo(&header[ip..], info.v6, info.protocol(), transport_len).fold();
                    write_u16(header, t + info.checksum_offset(), partial);
                    prefix.write(&vnet::for_joined(info, write.count as usize, run.segment_size), info.v6, lead);
                    write.skip = info.header_len as u32;
                    write.scratch = (at as u32, scratch.len() as u32);
                    continue;
                }
            };
            scratch.resize(at + prefix_len, 0);
            prefix.write(&header, v6, &mut scratch[at..]);
            write.scratch = (at as u32, scratch.len() as u32);
        }
    }
}

/// The first bytes of `packet`, up to [`MAX_HEADER`] of them, in one stretch, and how many
/// they are.
#[cold]
fn first_bytes(packet: &impl Parts) -> ([u8; MAX_HEADER], usize) {
    let (mut bytes, mut at) = ([0u8; MAX_HEADER], 0);
    each_in(packet, 0..MAX_HEADER, |stretch| {
        bytes[at..at + stretch.len()].copy_from_slice(stretch);
        at += stretch.len();
    });
    (bytes, at)
}

#[cold]
fn too_many() -> io::Error {
    invalid(&format!("a packet comes in more than the {} pieces a write takes", MAX_PIECES - 1))
}

fn too_long(max: usize) -> io::Error {
    invalid(&format!("a packet is longer than the {max} bytes the device takes"))
}

/// The writes of a planned batch.
pub struct Planned<'a, P> {
    plan: &'a Plan,
    packets: &'a [P],
}

impl<P> Clone for Planned<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for Planned<'_, P> {}

impl<P: Parts> Writes for Planned<'_, P> {
    fn count(&self) -> usize {
        self.plan.writes.len()
    }

    fn pieces<'a>(&'a self, index: usize, mut each: impl FnMut(&'a [u8])) {
        let write = &self.plan.writes[index];
        let scratch = &self.plan.scratch[write.scratch.0 as usize..write.scratch.1 as usize];
        if !scratch.is_empty() {
            each(scratch);
        }
        let skip = write.skip as usize;
        if write.end != END {
            each_in(&self.packets[write.first as usize], skip..write.end as usize, each);
            return;
        }
        let mut member = write.first;
        while member != END {
            each_in(&self.packets[member as usize], skip..usize::MAX, &mut each);
            member = self.plan.next[member as usize];
        }
    }
}

/// What joining needs to know about one packet.
struct Candidate {
    joinable: bool,
    header_len: usize,
    payload: usize,
    seq: u32,
    psh: bool,
    /// How many pieces the packet comes in.
    pieces: u32,
}

impl Candidate {
    fn new(head: Head<'_>, info: &Transport, takes: &Takes, pieces: u32) -> Candidate {
        let data = head.bytes;
        let payload = head.len - info.header_len;
        let plain_ip = info.v6 || info.transport - info.link == 20;
        if info.tcp {
            let t = info.transport;
            let flags = data[t + 13];
            Candidate {
                joinable: takes.tcp && plain_ip && flags & !PSH == ACK && payload > 0,
                header_len: info.header_len,
                payload,
                seq: u32::from_be_bytes(data[t + 4..t + 8].try_into().expect("four bytes")),
                psh: flags & PSH != 0,
                pieces,
            }
        } else {
            Candidate { joinable: takes.udp && plain_ip && payload > 0, header_len: info.header_len, payload, seq: 0, psh: false, pieces }
        }
    }
}

/// A flow: both addresses, both ports, the protocol and the IP version, packed into words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Key([u64; 5]);

impl Key {
    fn new(data: &[u8], info: &Transport) -> Key {
        let mut bytes = [0u8; 40];
        let ip = &data[info.link..];
        if info.v6 {
            bytes[..16].copy_from_slice(&ip[8..24]);
            bytes[16..32].copy_from_slice(&ip[24..40]);
        } else {
            bytes[..4].copy_from_slice(&ip[12..16]);
            bytes[16..20].copy_from_slice(&ip[16..20]);
        }
        bytes[32..36].copy_from_slice(&data[info.transport..info.transport + 4]);
        bytes[36] = info.protocol();
        bytes[37] = u8::from(info.v6);
        Key(core::array::from_fn(|i| u64::from_ne_bytes(bytes[i * 8..i * 8 + 8].try_into().expect("eight bytes"))))
    }

    fn hash(&self) -> usize {
        let mut hash = 0u64;
        for word in self.0 {
            hash = (hash.rotate_left(5) ^ word).wrapping_mul(0x517c_c1b7_2722_0a95);
        }
        (hash ^ (hash >> 29)) as usize
    }
}

/// The latest write of every flow in the batch, in an open-addressing table that is emptied by
/// moving to a new generation.
#[derive(Default)]
struct FlowTable {
    slots: Vec<Slot>,
    generation: u32,
}

#[derive(Clone, Copy, Default)]
struct Slot {
    generation: u32,
    write: u32,
    key: Key,
}

impl FlowTable {
    fn reset(&mut self, packets: usize) {
        let size = (packets * 2).next_power_of_two().max(64);
        if self.slots.len() < size {
            self.slots = vec![Slot::default(); size];
            self.generation = 0;
        }
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.slots.fill(Slot::default());
            self.generation = 1;
        }
    }

    fn position(&self, key: &Key) -> (usize, bool) {
        let mask = self.slots.len() - 1;
        let mut at = key.hash() & mask;
        loop {
            let slot = &self.slots[at];
            if slot.generation != self.generation {
                return (at, false);
            }
            if slot.key == *key {
                return (at, true);
            }
            at = (at + 1) & mask;
        }
    }

    fn get(&self, key: &Key) -> Option<u32> {
        let (at, found) = self.position(key);
        found.then(|| self.slots[at].write)
    }

    fn set(&mut self, key: Key, write: u32) {
        let (at, _) = self.position(&key);
        self.slots[at] = Slot { generation: self.generation, write, key };
    }
}

/// The bytes of write `index` of `writes`, gathered the way `writev` gathers them.
pub fn gather(writes: &impl Writes, index: usize, out: &mut Vec<u8>) {
    out.clear();
    writes.pieces(index, |piece| out.extend_from_slice(piece));
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::cut::Frame;
    use crate::framing::Family;
    use crate::packet::build::{Flow, payload};
    use crate::packet::{CWR, FIN, Packet, Pieces, TCP, link_len};

    const BSD: Family = Family { inet: 2, inet6: 24 };

    fn takes(prefix: Prefix, tcp: bool, udp: bool, ethernet: bool) -> Takes {
        Takes { framing: Framing { prefix, ethernet }, tcp, udp, udp_max_segments: 64, max_frame: usize::MAX }
    }

    /// A Linux device with offloads.
    fn virtio(udp: bool, ethernet: bool) -> Takes {
        takes(Prefix::Virtio(vnet::LEN), true, udp, ethernet)
    }

    /// A device that takes plain packets only.
    fn bare() -> Takes {
        takes(Prefix::None, false, false, false)
    }

    fn planned<P: Parts>(takes: &Takes, packets: &[P]) -> Plan {
        let mut plan = Plan::new();
        plan.plan_parts(takes, packets).unwrap();
        plan
    }

    fn write<P: Parts>(plan: &Plan, packets: &[P], index: usize) -> Vec<u8> {
        let mut out = Vec::new();
        gather(&plan.writes(packets), index, &mut out);
        out
    }

    fn counts(plan: &Plan) -> Vec<u32> {
        plan.writes.iter().map(|write| write.count).collect()
    }

    /// What the kernel does with a write: read the header, cut a segment, finish checksums.
    fn kernel_reads(write: &[u8]) -> Vec<Vec<u8>> {
        let header = Header::read(&write[..vnet::LEN]);
        let mut data = write[vnet::LEN..].to_vec();
        let (checksum, gso) = header.describe(&data, Some(0)).expect("a header the kernel accepts");
        let mut frame = Frame::new(&mut data, checksum, gso).expect("a frame the kernel accepts");
        let mut segments = frame.segments();
        let mut out = Vec::new();
        while let Some(mut packet) = segments.next() {
            packet.complete_checksum();
            out.push(packet.data().to_vec());
        }
        out
    }

    fn written<P: Parts>(plan: &Plan, packets: &[P]) -> Vec<Vec<u8>> {
        (0..plan.writes.len()).flat_map(|index| kernel_reads(&write(plan, packets, index))).collect()
    }

    fn tcp_run(flow: &mut Flow, seq: u32, sizes: &[usize], seed: u32) -> Vec<Vec<u8>> {
        let mut seq = seq;
        sizes
            .iter()
            .enumerate()
            .map(|(index, size)| {
                let packet = flow.packet(seq, &payload(seed + index as u32, *size));
                seq = seq.wrapping_add(*size as u32);
                flow.id = flow.id.wrapping_add(1);
                packet
            })
            .collect()
    }

    /// A segment as the kernel hands it over, its claims, and the packets it stands for.
    fn segment(flow: &Flow, size: usize, len: usize) -> (Vec<u8>, Checksum, Gso, Vec<Vec<u8>>) {
        crate::cut::tests::segment(flow, size, &payload(5, len))
    }

    #[test]
    fn joins_a_run_and_gives_it_back_unchanged() {
        for v6 in [false, true] {
            let mut flow = Flow::tcp(v6);
            let packets = tcp_run(&mut flow, 7, &[1400; 30], 1);
            let views: Vec<Packet<'_>> = packets.iter().map(|p| Packet::new(p).with_checksum(Checksum::Valid)).collect();
            let plan = planned(&virtio(true, false), &views);
            assert_eq!(counts(&plan), [30]);
            assert_eq!(written(&plan, &views), packets);
        }
    }

    #[test]
    fn writes_behind_a_tun_hdr_and_the_address_family() {
        for v6 in [false, true] {
            let mut flow = Flow::tcp(v6);
            let mut packets = tcp_run(&mut flow, 7, &[1400; 5], 1);
            packets.push(vec![0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
            let views: Vec<Packet<'_>> = packets.iter().map(|p| Packet::new(p)).collect();
            let plan = planned(&takes(Prefix::TunHdr { family: Some(BSD) }, true, false, false), &views);
            assert_eq!(counts(&plan), [5, 1]);
            let joined = write(&plan, &views, 0);
            let field = |at: usize| u16::from_ne_bytes([joined[at], joined[at + 1]]);
            // `TUN_H_TCP_CSUM` and `TUN_H_TCP_MSS`, and the segment size.
            assert_eq!((field(0), field(6)), (1 << 9 | 1 << 5, 1400));
            let family = if v6 { BSD.inet6 } else { BSD.inet };
            assert_eq!(joined[8..12], family.to_be_bytes());
            let mut data = joined[12..].to_vec();
            let ip_len = if v6 { 40 } else { 20 };
            let checksum = Checksum::Partial { start: ip_len, offset: 16 };
            let kind = if v6 { GsoKind::Tcp6 { ecn: false } } else { GsoKind::Tcp4 { ecn: false } };
            let gso = Gso { kind, segment_size: 1400, header_len: ip_len + 32 };
            let mut frame = Frame::new(&mut data, checksum, Some(gso)).unwrap();
            let mut segments = frame.segments();
            let mut out = Vec::new();
            while let Some(mut packet) = segments.next() {
                packet.complete_checksum();
                out.push(packet.data().to_vec());
            }
            assert_eq!(out, packets[..5]);
            let raw = write(&plan, &views, 1);
            assert_eq!(raw[..8], [0; 8], "a packet the system takes as it is");
            assert_eq!(raw[8..12], BSD.inet.to_be_bytes());
            assert_eq!(raw[12..], packets[5]);
        }
    }

    #[test]
    fn a_tun_hdr_carries_tcp_and_the_rest_is_carried_out_here() {
        let (tcp, tcp_checksum, tcp_gso, _) = segment(&Flow::tcp(false), 1400, 4000);
        let (udp, udp_checksum, udp_gso, udp_packets) = segment(&Flow::udp(false), 1400, 4000);
        let views = [
            Packet::new(&tcp).with_checksum(tcp_checksum).with_gso(tcp_gso),
            Packet::new(&udp).with_checksum(udp_checksum).with_gso(udp_gso),
            Packet::new(&tcp).with_checksum(tcp_checksum),
        ];
        let plan = planned(&takes(Prefix::TunHdr { family: Some(BSD) }, true, false, false), &views);
        assert_eq!(plan.writes.len(), 1 + 3 + 1);
        let carried = write(&plan, &views, 0);
        assert_eq!(u16::from_ne_bytes([carried[0], carried[1]]), 1 << 9 | 1 << 5, "the TCP segment goes whole");
        assert_eq!(carried[12..], tcp[..]);
        for (index, packet) in udp_packets.iter().enumerate() {
            let piece = write(&plan, &views, 1 + index);
            assert_eq!(piece[..8], [0; 8], "a cut packet leaves nothing to the system");
            assert_eq!(piece[8..12], BSD.inet.to_be_bytes());
            assert_eq!(&piece[12..], &packet[..]);
        }
        let last = write(&plan, &views, 4);
        assert_eq!(u16::from_ne_bytes([last[0], last[1]]), 1 << 9, "a TCP checksum alone is left to the system");
    }

    /// `packet` behind an Ethernet header with the addresses `mac` and a VLAN tag.
    fn ethernet(mac: u8, packet: &[u8]) -> Vec<u8> {
        let v6 = packet[0] >> 4 == 6;
        let mut frame = vec![mac; 12];
        frame.extend_from_slice(&[0x81, 0x00, 0x00, 0x07]);
        frame.extend_from_slice(if v6 { &[0x86, 0xdd] } else { &[0x08, 0x00] });
        frame.extend_from_slice(packet);
        frame
    }

    #[test]
    fn joins_ethernet_frames_and_gives_them_back_unchanged() {
        for v6 in [false, true] {
            let mut flow = Flow::tcp(v6);
            let packets = tcp_run(&mut flow, 7, &[1400; 12], 1);
            let mut frames: Vec<Vec<u8>> = packets.iter().take(8).map(|p| ethernet(2, p)).collect();
            frames.extend(packets.iter().skip(8).map(|p| ethernet(4, p)));
            frames.push(vec![6u8; 60]);
            let views: Vec<Packet<'_>> = frames.iter().map(|f| Packet::new(f)).collect();
            let plan = planned(&virtio(true, true), &views);
            assert_eq!(counts(&plan), [8, 4, 1], "frames with other addresses start a run of their own");
            let mut out = Vec::new();
            for index in 0..plan.writes.len() {
                let bytes = write(&plan, &views, index);
                let header = Header::read(&bytes[..vnet::LEN]);
                let mut data = bytes[vnet::LEN..].to_vec();
                if header == Header::default() {
                    out.push(data);
                    continue;
                }
                let (checksum, gso) = header.describe(&data, link_len(&data)).unwrap();
                let mut frame = Frame::new_ethernet(&mut data, checksum, gso).unwrap();
                let mut segments = frame.segments();
                while let Some(mut packet) = segments.next() {
                    packet.complete_checksum();
                    out.push(packet.data().to_vec());
                }
            }
            assert_eq!(out, frames, "v6 {v6}");
        }
    }

    #[test]
    fn a_run_ends_at_psh_a_short_packet_a_gap_or_64_kib() {
        let mut flow = Flow::tcp(false);
        let mut packets = tcp_run(&mut flow, 0, &[1000, 1000, 500, 1000], 1);
        flow.flags |= PSH;
        packets.extend(tcp_run(&mut flow, 3500, &[1000], 9));
        flow.flags = ACK;
        packets.extend(tcp_run(&mut flow, 4500, &[1000], 10));
        packets.extend(tcp_run(&mut flow, 9999, &[1000], 11));
        packets.extend(tcp_run(&mut flow, 10_999, &[1460; 50], 12));
        let views: Vec<Packet<'_>> = packets.iter().map(|p| Packet::new(p).with_checksum(Checksum::Valid)).collect();
        let plan = planned(&virtio(false, false), &views);
        assert_eq!(counts(&plan), [3, 2, 1, 1, 44, 6]);
        assert_eq!(written(&plan, &views), packets);
    }

    #[test]
    fn packets_that_cannot_be_joined_keep_their_order() {
        let mut a = Flow::tcp(false);
        let mut b = Flow::tcp(false);
        b.src_port = 5555;
        let mut packets = Vec::new();
        packets.extend(tcp_run(&mut a, 0, &[1000, 1000], 1));
        a.flags = ACK | FIN;
        packets.extend(tcp_run(&mut a, 2000, &[100], 2));
        a.flags = ACK;
        packets.extend(tcp_run(&mut b, 0, &[1000, 1000], 3));
        a.ack += 1;
        packets.extend(tcp_run(&mut a, 2101, &[1000, 1000], 4));
        a.flags = ACK | CWR;
        packets.extend(tcp_run(&mut a, 4101, &[1000], 5));
        let mut corrupt = Flow::udp(true).packet(0, &payload(1, 300));
        corrupt[100] ^= 0xff;
        packets.push(corrupt);
        packets.push(vec![0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        let views: Vec<Packet<'_>> = packets.iter().map(|p| Packet::new(p)).collect();
        let plan = planned(&virtio(true, false), &views);
        assert_eq!(counts(&plan), [2, 1, 2, 2, 1, 1, 1]);
        let raw_corrupt = write(&plan, &views, 5);
        assert_eq!(Header::read(&raw_corrupt), Header::default());
        assert_eq!(&raw_corrupt[vnet::LEN..], &packets[packets.len() - 2][..]);
        // The corrupt packet is taken as it was written instead of failing a checksum check.
        let out: Vec<Vec<u8>> = (0..plan.writes.len())
            .flat_map(|index| {
                let bytes = write(&plan, &views, index);
                if index == 5 { vec![bytes[vnet::LEN..].to_vec()] } else { kernel_reads(&bytes) }
            })
            .collect();
        assert_eq!(out, packets);
    }

    #[test]
    fn udp_runs_respect_the_segment_limit() {
        let first = Flow::udp(false).id;
        let packets: Vec<Vec<u8>> = (0..100u32)
            .map(|i| Flow { id: first.wrapping_add(i as u16), ..Flow::udp(false) }.packet(0, &payload(i, 200)))
            .collect();
        let views: Vec<Packet<'_>> = packets.iter().map(|p| Packet::new(p).with_checksum(Checksum::Valid)).collect();
        let plan = planned(&virtio(true, false), &views);
        assert_eq!(counts(&plan), [64, 36]);
        assert_eq!(written(&plan, &views), packets);
        let without = planned(&virtio(false, false), &views);
        assert_eq!(without.writes.len(), 100);
        assert_eq!(written(&without, &views), packets);
    }

    #[test]
    fn segments_and_partial_packets_pass_through() {
        let (whole, checksum, gso, _) = segment(&Flow::tcp(false), 1000, 3000);
        let views = [Packet::new(&whole).with_checksum(checksum).with_gso(gso), Packet::new(&whole).with_checksum(checksum)];
        let mut plan = planned(&virtio(true, false), &views);
        assert_eq!(plan.writes.len(), 2);
        let first = write(&plan, &views, 0);
        assert_eq!(Header::read(&first).gso_size, 1000);
        assert_eq!(kernel_reads(&first).len(), 3);
        let second = write(&plan, &views, 1);
        assert_eq!(Header::read(&second).flags, vnet::NEEDS_CSUM);
        assert_eq!(&second[vnet::LEN..], &whole[..]);
        let bad = Gso { segment_size: 0, ..gso };
        assert!(plan.plan(&virtio(true, false), &[Packet::new(&whole).with_checksum(checksum).with_gso(bad)]).is_err());
    }

    #[test]
    fn a_udp_segment_is_cut_for_a_device_without_udp_segments() {
        let mut flow = Flow::udp(false);
        flow.src_port = 7000;
        let (whole, checksum, gso, expected) = segment(&flow, 1200, 5000);
        let before = Flow::udp(false).packet(0, &payload(1, 100));
        // A datagram of the segment's flow after it: it stays behind the cut packets.
        let after = flow.packet(0, &payload(2, 100));
        let views = [
            Packet::new(&before).with_checksum(Checksum::Valid),
            Packet::new(&whole).with_checksum(checksum).with_gso(gso),
            Packet::new(&after).with_checksum(Checksum::Valid),
        ];
        let plan = planned(&virtio(false, false), &views);
        let out = written(&plan, &views);
        assert_eq!(out.len(), 1 + expected.len() + 1);
        assert_eq!(out[0], before);
        assert_eq!(out[1..=expected.len()], expected[..]);
        assert_eq!(out[expected.len() + 1], after);
        for index in 1..=expected.len() {
            assert_eq!(Header::read(&write(&plan, &views, index)), Header::default(), "nothing is left to the device");
        }
        let carried = planned(&virtio(true, false), &views);
        assert_eq!(Header::read(&write(&carried, &views, 1)).gso_type, vnet::GSO_UDP_L4);
        assert_eq!(written(&carried, &views).len(), out.len());
    }

    #[test]
    fn a_plain_device_gets_whole_packets_with_complete_checksums() {
        let (whole, checksum, gso, expected) = segment(&Flow::tcp(true), 1500, 4000);
        let complete = Flow::tcp(true).packet(1000, &payload(5, 4000));
        let other = Flow::udp(false).packet(0, &payload(2, 10));
        let views = [
            Packet::new(&whole).with_checksum(checksum).with_gso(gso),
            Packet::new(&whole).with_checksum(checksum),
            Packet::new(&other),
        ];
        let mut plan = planned(&bare(), &views);
        assert_eq!(plan.writes.len(), 5);
        for (index, packet) in expected.iter().enumerate() {
            assert_eq!(write(&plan, &views, index), *packet);
        }
        assert_eq!(write(&plan, &views, 3), complete);
        assert_eq!(write(&plan, &views, 4), other);
        let mut pieces = 0;
        plan.writes(&views).pieces(4, |_| pieces += 1);
        assert_eq!(pieces, 1, "a packet that needs nothing is written from where it lies");
        assert!(plan.plan(&bare(), &[Packet::new(&other).with_checksum(Checksum::Partial { start: 20, offset: 100 })]).is_err());
        assert!(plan.plan(&bare(), &[Packet::new(&other).with_gso(gso)]).is_err(), "a segment without a partial checksum");
        let family = planned(&takes(Prefix::Family(BSD), false, false, false), &views);
        assert_eq!(write(&family, &views, 0), [&BSD.inet6.to_be_bytes()[..], &expected[0]].concat());
        assert_eq!(write(&family, &views, 4), [&BSD.inet.to_be_bytes()[..], &other].concat());
    }

    #[test]
    fn frames_longer_than_the_device_takes_are_refused() {
        let (whole, checksum, gso, expected) = segment(&Flow::tcp(false), 1400, 4000);
        let limit = |max_frame| Takes { max_frame, ..bare() };
        let views = [Packet::new(&whole).with_checksum(checksum).with_gso(gso)];
        let mut plan = Plan::new();
        plan.plan(&limit(expected[0].len()), &views).unwrap();
        assert_eq!(plan.writes.len(), 3);
        assert!(plan.plan(&limit(expected[0].len() - 1), &views).is_err(), "a cut packet that is too long");
        assert!(plan.plan(&limit(1500), &[Packet::new(&whole)]).is_err());
        assert!(plan.plan(&limit(1500), &[Packet::new(&whole).with_checksum(checksum)]).is_err());
        plan.plan(&limit(1500), &[Packet::new(&expected[0])]).unwrap();
    }

    #[derive(Debug, Clone)]
    struct Step {
        flow: usize,
        size: usize,
        psh: bool,
    }

    fn step() -> impl Strategy<Value = Step> {
        (0usize..4, prop_oneof![Just(1400usize), 1usize..1500], prop::bool::weighted(0.1))
            .prop_map(|(flow, size, psh)| Step { flow, size, psh })
    }

    proptest! {
        #[test]
        fn any_batch_comes_back_out_in_flow_order(steps in prop::collection::vec(step(), 1..200), udp in any::<bool>()) {
            let mut flows: Vec<Flow> = (0..4).map(|i| {
                let mut flow = if i < 2 { Flow::tcp(i == 1) } else { Flow::udp(i == 3) };
                flow.src_port = 1000 + i as u16;
                flow
            }).collect();
            let mut seqs = [0u32; 4];
            let mut packets = Vec::new();
            for (index, step) in steps.iter().enumerate() {
                let flow = &mut flows[step.flow];
                if flow.tcp {
                    flow.flags = if step.psh { ACK | PSH } else { ACK };
                }
                packets.push((step.flow, flow.packet(seqs[step.flow], &payload(index as u32, step.size))));
                seqs[step.flow] = seqs[step.flow].wrapping_add(step.size as u32);
                flow.id = flow.id.wrapping_add(1);
            }
            let views: Vec<Packet<'_>> = packets.iter().map(|(_, p)| Packet::new(p)).collect();
            let plan = planned(&virtio(udp, false), &views);
            let out = written(&plan, &views);
            prop_assert_eq!(out.len(), packets.len());
            for flow in 0..4 {
                let sent: Vec<&Vec<u8>> = packets.iter().filter(|(f, _)| *f == flow).map(|(_, p)| p).collect();
                let got: Vec<&Vec<u8>> = out.iter().filter(|p| {
                    let info = Transport::read(p, 0).unwrap();
                    u16::from_be_bytes([p[info.transport], p[info.transport + 1]]) == 1000 + flow as u16
                }).collect();
                prop_assert_eq!(got, sent);
            }
        }
    }

    /// A packet in pieces: its first bytes, then stretches of one size.
    struct Split {
        head: Vec<u8>,
        body: Vec<Vec<u8>>,
        checksum: Checksum,
        gso: Option<Gso>,
    }

    impl Split {
        fn new(packet: &Packet<'_>, head: usize, size: usize) -> Split {
            let (head, body) = packet.data.split_at(head.min(packet.data.len()));
            Split { head: head.to_vec(), body: body.chunks(size).map(<[u8]>::to_vec).collect(), checksum: packet.checksum, gso: packet.gso }
        }

        fn view(&self) -> Pieces<'_, Vec<u8>> {
            Pieces { head: &self.head, body: &self.body, checksum: self.checksum, gso: self.gso }
        }
    }

    fn every_write<P: Parts>(plan: &Plan, packets: &[P]) -> Vec<Vec<u8>> {
        (0..plan.writes.len()).map(|index| write(plan, packets, index)).collect()
    }

    /// Where the headers of a TCP or UDP packet end; 20 bytes in for any other.
    fn headers(packet: &[u8]) -> usize {
        Transport::read(packet, 0).map_or(20, |info| info.header_len)
    }

    #[test]
    fn pieces_behind_their_headers_are_planned_like_the_packets_whole() {
        let mut packets = Vec::new();
        for v6 in [false, true] {
            packets.extend(tcp_run(&mut Flow::tcp(v6), 7, &[1400; 30], 1));
            let first = Flow::udp(v6).id;
            packets.extend((0..40u32).map(|i| Flow { id: first.wrapping_add(i as u16), ..Flow::udp(v6) }.packet(0, &payload(i, 900))));
        }
        packets.push(vec![0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 8, 0, 0xf7, 0xff, 0, 0, 0, 0]);
        let mut other = Flow::tcp(true);
        other.src_port = 9;
        let (tcp, tcp_checksum, tcp_gso, _) = segment(&other, 1400, 9000);
        let mut datagrams = Flow::udp(false);
        datagrams.src_port = 9;
        let (udp, udp_checksum, udp_gso, _) = segment(&datagrams, 1200, 5000);
        let mut views: Vec<Packet<'_>> = packets.iter().map(|p| Packet::new(p)).collect();
        views.push(Packet::new(&tcp).with_checksum(tcp_checksum).with_gso(tcp_gso));
        views.push(Packet::new(&tcp).with_checksum(tcp_checksum));
        views.push(Packet::new(&udp).with_checksum(udp_checksum).with_gso(udp_gso));
        let splits: Vec<Split> =
            views.iter().enumerate().map(|(index, view)| Split::new(view, headers(view.data), 16 + index * 37 % 977)).collect();
        let pieces: Vec<Pieces<'_, Vec<u8>>> = splits.iter().map(Split::view).collect();
        let devices = [
            virtio(true, false),
            virtio(false, false),
            bare(),
            takes(Prefix::Family(BSD), false, false, false),
            takes(Prefix::TunHdr { family: Some(BSD) }, true, false, false),
        ];
        for device in devices {
            let (whole, cut) = (planned(&device, &views), planned(&device, &pieces));
            assert_eq!(counts(&cut), counts(&whole), "{device:?}");
            assert_eq!(every_write(&cut, &pieces), every_write(&whole, &views), "{device:?}");
        }
    }

    #[test]
    fn a_write_takes_no_more_pieces_than_the_system_does() {
        let packet = Flow::udp(false).packet(0, &payload(1, 1100));
        let view = Packet::new(&packet).with_checksum(Checksum::Valid);
        let most = Split::new(&view, 106, 1);
        assert_eq!(most.body.len(), MAX_PIECES - 2);
        let plan = planned(&virtio(true, false), &[most.view()]);
        let mut count = 0;
        plan.writes(&[most.view()]).pieces(0, |_| count += 1);
        assert_eq!(count, MAX_PIECES, "the device's prefix, the head and the rest a byte at a time");
        let more = Split::new(&view, 105, 1);
        assert!(Plan::new().plan_parts(&virtio(true, false), &[more.view()]).is_err());

        let packets = tcp_run(&mut Flow::tcp(false), 0, &[1400; 10], 1);
        let splits: Vec<Split> =
            packets.iter().map(|p| Split::new(&Packet::new(p).with_checksum(Checksum::Valid), headers(p), 4)).collect();
        let pieces: Vec<Pieces<'_, Vec<u8>>> = splits.iter().map(Split::view).collect();
        let plan = planned(&virtio(true, false), &pieces);
        assert_eq!(counts(&plan), [2; 5], "a third packet of 351 pieces is one too many for a write");
        assert_eq!(written(&plan, &pieces), packets);
    }

    #[test]
    fn the_address_family_is_read_from_the_first_byte_wherever_it_lies() {
        let packet = Flow::udp(true).packet(0, &payload(1, 100));
        let body = [Vec::new(), packet.clone()];
        let pieces = [Pieces::new(&[], &body)];
        let plan = planned(&takes(Prefix::Family(BSD), false, false, false), &pieces);
        assert_eq!(write(&plan, &pieces, 0), [&BSD.inet6.to_be_bytes()[..], &packet].concat());
        let nothing: [Pieces<'_, Vec<u8>>; 1] = [Pieces::new(&[], &[])];
        let plan = planned(&bare(), &nothing);
        assert_eq!(every_write(&plan, &nothing), [Vec::<u8>::new()]);
    }

    proptest! {
        #[test]
        fn any_pieces_of_any_batch_come_back_out_in_flow_order(
            steps in prop::collection::vec((step(), 0usize..120, 2usize..800), 1..120),
            udp in any::<bool>(),
        ) {
            let mut flows: Vec<Flow> = (0..4).map(|i| {
                let mut flow = if i < 2 { Flow::tcp(i == 1) } else { Flow::udp(i == 3) };
                flow.src_port = 1000 + i as u16;
                flow
            }).collect();
            let mut seqs = [0u32; 4];
            let mut packets = Vec::new();
            for (index, (step, _, _)) in steps.iter().enumerate() {
                let flow = &mut flows[step.flow];
                if flow.tcp {
                    flow.flags = if step.psh { ACK | PSH } else { ACK };
                }
                packets.push((step.flow, flow.packet(seqs[step.flow], &payload(index as u32, step.size))));
                seqs[step.flow] = seqs[step.flow].wrapping_add(step.size as u32);
                flow.id = flow.id.wrapping_add(1);
            }
            let splits: Vec<Split> = packets.iter().zip(&steps)
                .map(|((_, p), (_, head, size))| Split::new(&Packet::new(p), *head, *size))
                .collect();
            let pieces: Vec<Pieces<'_, Vec<u8>>> = splits.iter().map(Split::view).collect();
            let plan = planned(&virtio(udp, false), &pieces);
            let out = written(&plan, &pieces);
            prop_assert_eq!(out.len(), packets.len());
            for flow in 0..4 {
                let sent: Vec<&Vec<u8>> = packets.iter().filter(|(f, _)| *f == flow).map(|(_, p)| p).collect();
                let got: Vec<&Vec<u8>> = out.iter().filter(|p| {
                    let info = Transport::read(p, 0).unwrap();
                    u16::from_be_bytes([p[info.transport], p[info.transport + 1]]) == 1000 + flow as u16
                }).collect();
                prop_assert_eq!(got, sent);
            }
        }

        #[test]
        fn a_segment_in_any_pieces_is_cut_and_completed_like_the_segment_whole(
            tcp in any::<bool>(),
            v6 in any::<bool>(),
            size in 1usize..1500,
            length in 1usize..9000,
            head in 0usize..120,
            piece in 10usize..3000,
        ) {
            let flow = if tcp { Flow::tcp(v6) } else { Flow::udp(v6) };
            let (whole, checksum, gso, _) = segment(&flow, size, length);
            let views = [Packet::new(&whole).with_checksum(checksum).with_gso(gso), Packet::new(&whole).with_checksum(checksum)];
            let splits = views.map(|view| Split::new(&view, head, piece));
            let pieces = [splits[0].view(), splits[1].view()];
            for device in [bare(), takes(Prefix::TunHdr { family: Some(BSD) }, false, false, false), virtio(false, false)] {
                let (expected, cut) = (planned(&device, &views), planned(&device, &pieces));
                prop_assert_eq!(every_write(&cut, &pieces), every_write(&expected, &views));
            }
        }
    }

    #[test]
    fn the_flow_key_tells_protocols_apart() {
        let tcp = Flow::tcp(false).packet(0, &payload(1, 10));
        let udp = Flow::udp(false).packet(0, &payload(1, 10));
        let (a, b) = (Transport::read(&tcp, 0).unwrap(), Transport::read(&udp, 0).unwrap());
        assert_eq!(a.protocol(), TCP);
        assert_ne!(Key::new(&tcp, &a), Key::new(&udp, &b));
    }
}
