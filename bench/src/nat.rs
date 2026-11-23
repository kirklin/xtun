//! The address rewrite of the reflector, with checksums kept right incrementally.

use std::net::IpAddr;

use xtun::checksum::Sum;

/// Addresses by IP version: the interface, the address clients dial, and the address the server
/// sees them come from.
pub struct Nat {
    pub v4: [IpAddr; 3],
    pub v6: [IpAddr; 3],
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

/// Rewrites one packet in place. `partial` says the transport checksum field holds only the
/// pseudo header sum. Returns false for a packet that is not for the reflector.
pub fn rewrite(packet: &mut [u8], partial: bool, nat: &Nat) -> bool {
    if packet.is_empty() {
        return false;
    }
    let v6 = packet[0] >> 4 == 6;
    let ([local, peer, other], src_at, dst_at, len) = if v6 { (nat.v6, 8, 24, 16) } else { (nat.v4, 12, 16, 4) };
    if packet.len() < dst_at + len {
        return false;
    }
    let dst = &packet[dst_at..dst_at + len];
    let (new_src, new_dst) = if dst == octets(peer) {
        (octets(other), octets(local))
    } else if dst == octets(other) {
        (octets(peer), octets(local))
    } else {
        return false;
    };
    let old = Sum::ZERO.bytes(&packet[src_at..src_at + len]).bytes(&packet[dst_at..dst_at + len]);
    let new = Sum::ZERO.bytes(&new_src).bytes(&new_dst);
    packet[src_at..src_at + len].copy_from_slice(&new_src);
    packet[dst_at..dst_at + len].copy_from_slice(&new_dst);
    let ip_len = if v6 { 40 } else { usize::from(packet[0] & 0x0f) * 4 };
    if !v6 {
        let value = u16::from_be_bytes([packet[10], packet[11]]);
        let updated = !Sum::ZERO.word(!value).word(!old.fold()).combine(new).fold();
        packet[10..12].copy_from_slice(&updated.to_be_bytes());
    }
    let protocol = packet[if v6 { 6 } else { 9 }];
    let field = match protocol {
        6 => 16,
        17 => 6,
        58 => 2,
        _ => return true,
    };
    let at = ip_len + field;
    if at + 2 > packet.len() {
        return true;
    }
    let value = u16::from_be_bytes([packet[at], packet[at + 1]]);
    let updated = if partial {
        Sum::ZERO.word(value).word(!old.fold()).combine(new).fold()
    } else if protocol == 17 && !v6 && value == 0 {
        0
    } else {
        !Sum::ZERO.word(!value).word(!old.fold()).combine(new).fold()
    };
    packet[at..at + 2].copy_from_slice(&updated.to_be_bytes());
    true
}
