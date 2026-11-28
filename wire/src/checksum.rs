//! The Internet checksum of RFC 1071.
//!
//! A [`Sum`] collects data unfolded and is folded to 16 bits once, at the end. Data is added as
//! native-endian words of up to 128 bits: one's complement addition does not depend on byte order
//! (RFC 1071, section 2), so the folded value only has its two bytes swapped on little-endian
//! machines to equal the sum of big-endian 16-bit words.

/// A one's complement sum that data is still being added to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sum {
    /// The sum of native-endian words, with every carry out of bit 63 added back in.
    acc: u64,
    /// Whether an odd number of bytes has been added, so the next byte is the low half of a word.
    odd: bool,
}

impl Sum {
    /// The sum of nothing.
    pub const ZERO: Sum = Sum { acc: 0, odd: false };

    /// Adds the next bytes of the checksummed range.
    #[inline]
    pub fn bytes(self, data: &[u8]) -> Sum {
        if data.is_empty() {
            return self;
        }
        let part = native(data);
        let part = if self.odd { u64::from(fold64(part).swap_bytes()) } else { part };
        Sum { acc: add(self.acc, part), odd: self.odd ^ (data.len() % 2 == 1) }
    }

    /// Adds a 16-bit value, such as a length or a checksum field read as big-endian, as its two
    /// bytes in that order would be added at the place the sum has reached.
    #[inline]
    pub fn word(self, value: u16) -> Sum {
        let part = if self.odd { value.to_le() } else { value.to_be() };
        Sum { acc: add(self.acc, u64::from(part)), odd: self.odd }
    }

    /// Adds the unfolded value of another sum that started at an even offset.
    #[inline]
    pub fn combine(self, other: Sum) -> Sum {
        let part = if self.odd { u64::from(fold64(other.acc).swap_bytes()) } else { other.acc };
        Sum { acc: add(self.acc, part), odd: self.odd ^ other.odd }
    }

    /// The 16-bit one's complement sum, as a big-endian field would read it.
    #[inline]
    pub fn fold(self) -> u16 {
        u16::from_be(fold64(self.acc))
    }

    /// The value for a checksum field: the complement of the folded sum. The sum of a header is
    /// never zero, so the field is never `0xffff` (RFC 1624, section 3).
    #[inline]
    pub fn checksum(self) -> u16 {
        !self.fold()
    }

    /// The value for a UDP checksum field: as [`Sum::checksum`], with a result of zero written as
    /// `0xffff`, the same number in one's complement, since a zero field says that a datagram
    /// has no checksum (RFC 768).
    #[inline]
    pub fn udp_checksum(self) -> u16 {
        match self.checksum() {
            0 => 0xffff,
            value => value,
        }
    }
}

/// The sum of an IPv4 pseudo header.
#[inline]
pub fn pseudo_v4(src: &[u8], dst: &[u8], protocol: u8, length: u16) -> Sum {
    Sum::ZERO.bytes(&src[..4]).bytes(&dst[..4]).word(u16::from(protocol)).word(length)
}

/// The sum of an IPv6 pseudo header.
#[inline]
pub fn pseudo_v6(src: &[u8], dst: &[u8], protocol: u8, length: u32) -> Sum {
    Sum::ZERO
        .bytes(&src[..16])
        .bytes(&dst[..16])
        .word((length >> 16) as u16)
        .word(length as u16)
        .word(u16::from(protocol))
}

/// Copies `src` into `dst`, which must have the same length, and sums the bytes on the way.
#[inline]
pub fn copy(dst: &mut [u8], src: &[u8]) -> Sum {
    assert_eq!(dst.len(), src.len(), "copy needs two slices of the same length");
    if src.is_empty() {
        return Sum::ZERO;
    }
    let acc = copy_native(dst, src);
    Sum { acc, odd: src.len() % 2 == 1 }
}

#[inline]
fn add(a: u64, b: u64) -> u64 {
    let (sum, carry) = a.overflowing_add(b);
    sum + u64::from(carry)
}

/// Folds to 16 bits. 2^16 is 1 modulo 0xffff, so cutting at any multiple of 16 bits and adding
/// the pieces keeps the value of the sum.
#[inline]
fn fold64(acc: u64) -> u16 {
    let acc = (acc & 0xffff_ffff) + (acc >> 32);
    let acc = (acc & 0xffff_ffff) + (acc >> 32);
    let acc = (acc & 0xffff) + (acc >> 16);
    let acc = (acc & 0xffff) + (acc >> 16);
    let acc = (acc & 0xffff) + (acc >> 16);
    acc as u16
}

const SIMD_THRESHOLD: usize = 64;

#[inline]
fn native(data: &[u8]) -> u64 {
    if data.len() >= SIMD_THRESHOLD {
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        // SAFETY: the build targets processors with NEON.
        return unsafe { neon::sum(data) };
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: the processor supports AVX2.
            return unsafe { avx2::sum(data) };
        }
    }
    scalar::sum(data)
}

#[inline]
fn copy_native(dst: &mut [u8], src: &[u8]) -> u64 {
    if src.len() >= SIMD_THRESHOLD {
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        // SAFETY: the build targets processors with NEON.
        return unsafe { neon::copy(dst, src) };
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: the processor supports AVX2.
            return unsafe { avx2::copy(dst, src) };
        }
    }
    scalar::copy(dst, src)
}

mod scalar {
    use super::add;

    /// Sums 32-bit halves of 64-bit words into two accumulators: 2^32 words fit before either
    /// can overflow, far more than any packet.
    pub fn sum(data: &[u8]) -> u64 {
        let (words, rest) = data.as_chunks::<8>();
        let (mut lo, mut hi) = (0u64, 0u64);
        for word in words {
            let word = u64::from_ne_bytes(*word);
            lo += word & 0xffff_ffff;
            hi += word >> 32;
        }
        add(add(lo, hi), tail(rest))
    }

    pub fn copy(dst: &mut [u8], src: &[u8]) -> u64 {
        let (from, rest) = src.as_chunks::<8>();
        let (to, rest_to) = dst.as_chunks_mut::<8>();
        let (mut lo, mut hi) = (0u64, 0u64);
        for (bytes, out) in from.iter().zip(to) {
            *out = *bytes;
            let word = u64::from_ne_bytes(*bytes);
            lo += word & 0xffff_ffff;
            hi += word >> 32;
        }
        rest_to.copy_from_slice(rest);
        add(add(lo, hi), tail(rest))
    }

    /// The last bytes, fewer than eight. A final odd byte is the high half of a big-endian word,
    /// which is the low half in native order on a little-endian machine: `from_ne_bytes([b, 0])`
    /// is right on both.
    #[inline]
    pub fn tail(mut rest: &[u8]) -> u64 {
        let mut acc = 0u64;
        if rest.len() >= 4 {
            acc += u64::from(u32::from_ne_bytes(rest[..4].try_into().expect("four bytes")));
            rest = &rest[4..];
        }
        if rest.len() >= 2 {
            acc += u64::from(u16::from_ne_bytes([rest[0], rest[1]]));
            rest = &rest[2..];
        }
        if let [last] = rest {
            acc += u64::from(u16::from_ne_bytes([*last, 0]));
        }
        acc
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod neon {
    use core::arch::aarch64::{
        uint64x2_t, vaddq_u64, vdupq_n_u64, vgetq_lane_u64, vld1q_u8, vpadalq_u32, vreinterpretq_u32_u8, vst1q_u8,
    };

    use super::{add, scalar};

    /// Pairwise adds 32-bit lanes into 64-bit accumulators, sixteen bytes per instruction. A
    /// lane grows by less than 2^33 per step, so it cannot overflow on any real input.
    #[target_feature(enable = "neon")]
    pub fn sum(data: &[u8]) -> u64 {
        let mut acc = [vdupq_n_u64(0); 4];
        let (blocks, rest) = data.as_chunks::<64>();
        for block in blocks {
            let p = block.as_ptr();
            // SAFETY: `block` has 64 readable bytes; the loads need no alignment.
            unsafe {
                acc[0] = vpadalq_u32(acc[0], vreinterpretq_u32_u8(vld1q_u8(p)));
                acc[1] = vpadalq_u32(acc[1], vreinterpretq_u32_u8(vld1q_u8(p.add(16))));
                acc[2] = vpadalq_u32(acc[2], vreinterpretq_u32_u8(vld1q_u8(p.add(32))));
                acc[3] = vpadalq_u32(acc[3], vreinterpretq_u32_u8(vld1q_u8(p.add(48))));
            }
        }
        let (lanes, rest) = rest.as_chunks::<16>();
        for lane in lanes {
            // SAFETY: `lane` has 16 readable bytes.
            acc[0] = vpadalq_u32(acc[0], vreinterpretq_u32_u8(unsafe { vld1q_u8(lane.as_ptr()) }));
        }
        add(reduce(acc), scalar::sum(rest))
    }

    #[target_feature(enable = "neon")]
    pub fn copy(dst: &mut [u8], src: &[u8]) -> u64 {
        let mut acc = [vdupq_n_u64(0); 4];
        let (from, rest) = src.as_chunks::<64>();
        let (to, rest_to) = dst.as_chunks_mut::<64>();
        for (block, out) in from.iter().zip(to) {
            let (p, q) = (block.as_ptr(), out.as_mut_ptr());
            // SAFETY: both blocks have 64 bytes; loads and stores need no alignment.
            unsafe {
                let v0 = vld1q_u8(p);
                let v1 = vld1q_u8(p.add(16));
                let v2 = vld1q_u8(p.add(32));
                let v3 = vld1q_u8(p.add(48));
                vst1q_u8(q, v0);
                vst1q_u8(q.add(16), v1);
                vst1q_u8(q.add(32), v2);
                vst1q_u8(q.add(48), v3);
                acc[0] = vpadalq_u32(acc[0], vreinterpretq_u32_u8(v0));
                acc[1] = vpadalq_u32(acc[1], vreinterpretq_u32_u8(v1));
                acc[2] = vpadalq_u32(acc[2], vreinterpretq_u32_u8(v2));
                acc[3] = vpadalq_u32(acc[3], vreinterpretq_u32_u8(v3));
            }
        }
        add(reduce(acc), scalar::copy(rest_to, rest))
    }

    #[target_feature(enable = "neon")]
    fn reduce(acc: [uint64x2_t; 4]) -> u64 {
        let pairs = [vaddq_u64(acc[0], acc[1]), vaddq_u64(acc[2], acc[3])];
        pairs.iter().fold(0, |total, pair| add(add(total, vgetq_lane_u64(*pair, 0)), vgetq_lane_u64(*pair, 1)))
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use core::arch::x86_64::{
        __m256i, _mm256_add_epi64, _mm256_and_si256, _mm256_loadu_si256, _mm256_set1_epi64x, _mm256_setzero_si256,
        _mm256_srli_epi64, _mm256_storeu_si256,
    };

    use super::{add, scalar};

    /// Adds the low and high 32 bits of every 64-bit lane into 64-bit accumulators.
    ///
    /// # Safety
    ///
    /// The processor must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn sum(data: &[u8]) -> u64 {
        let mask = _mm256_set1_epi64x(0xffff_ffff);
        let (mut lo, mut hi) = (_mm256_setzero_si256(), _mm256_setzero_si256());
        let (blocks, rest) = data.as_chunks::<64>();
        for block in blocks {
            let p = block.as_ptr().cast::<__m256i>();
            // SAFETY: `block` has 64 readable bytes; unaligned loads are allowed.
            let (v0, v1) = unsafe { (_mm256_loadu_si256(p), _mm256_loadu_si256(p.add(1))) };
            lo = _mm256_add_epi64(lo, _mm256_and_si256(v0, mask));
            hi = _mm256_add_epi64(hi, _mm256_srli_epi64(v0, 32));
            lo = _mm256_add_epi64(lo, _mm256_and_si256(v1, mask));
            hi = _mm256_add_epi64(hi, _mm256_srli_epi64(v1, 32));
        }
        add(add(reduce(lo), reduce(hi)), scalar::sum(rest))
    }

    /// # Safety
    ///
    /// The processor must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn copy(dst: &mut [u8], src: &[u8]) -> u64 {
        let mask = _mm256_set1_epi64x(0xffff_ffff);
        let (mut lo, mut hi) = (_mm256_setzero_si256(), _mm256_setzero_si256());
        let (from, rest) = src.as_chunks::<64>();
        let (to, rest_to) = dst.as_chunks_mut::<64>();
        for (block, out) in from.iter().zip(to) {
            let p = block.as_ptr().cast::<__m256i>();
            let q = out.as_mut_ptr().cast::<__m256i>();
            // SAFETY: both blocks have 64 bytes; unaligned loads and stores are allowed.
            unsafe {
                let (v0, v1) = (_mm256_loadu_si256(p), _mm256_loadu_si256(p.add(1)));
                _mm256_storeu_si256(q, v0);
                _mm256_storeu_si256(q.add(1), v1);
                lo = _mm256_add_epi64(lo, _mm256_and_si256(v0, mask));
                hi = _mm256_add_epi64(hi, _mm256_srli_epi64(v0, 32));
                lo = _mm256_add_epi64(lo, _mm256_and_si256(v1, mask));
                hi = _mm256_add_epi64(hi, _mm256_srli_epi64(v1, 32));
            }
        }
        add(add(reduce(lo), reduce(hi)), scalar::copy(rest_to, rest))
    }

    #[target_feature(enable = "avx2")]
    fn reduce(v: __m256i) -> u64 {
        let mut lanes = [0u64; 4];
        // SAFETY: `lanes` has 32 writable bytes.
        unsafe { _mm256_storeu_si256(lanes.as_mut_ptr().cast(), v) };
        lanes.iter().fold(0, |total, lane| add(total, *lane))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// RFC 1071 as written: big-endian 16-bit words, a final odd byte padded with zero.
    fn reference(data: &[u8]) -> u16 {
        let mut acc = 0u32;
        for pair in data.chunks(2) {
            let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
            acc += u32::from(word);
            acc = (acc & 0xffff) + (acc >> 16);
        }
        acc as u16
    }

    #[test]
    fn known_ipv4_header() {
        // RFC 1071 example data and a captured IPv4 header with its checksum zeroed.
        assert_eq!(Sum::ZERO.bytes(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]).fold(), 0xddf2);
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8,
            0x00, 0xc7,
        ];
        assert_eq!(Sum::ZERO.bytes(&header).checksum(), 0xb861);
    }

    #[test]
    fn folds_to_ffff_only_for_a_nonzero_multiple() {
        assert_eq!(Sum::ZERO.fold(), 0);
        assert_eq!(Sum::ZERO.checksum(), 0xffff);
        assert_eq!(Sum::ZERO.bytes(&[0xff, 0xff]).fold(), 0xffff);
        assert_eq!(Sum::ZERO.word(0x1234).word(!0x1234).fold(), 0xffff);
    }

    #[test]
    fn only_udp_writes_a_zero_checksum_as_ffff() {
        let all_ones = Sum::ZERO.word(0x1234).word(!0x1234);
        assert_eq!((all_ones.checksum(), all_ones.udp_checksum()), (0, 0xffff));
        let other = Sum::ZERO.bytes(&[0x12, 0x34]);
        assert_eq!((other.checksum(), other.udp_checksum()), (!0x1234, !0x1234));
    }

    #[test]
    fn pseudo_headers() {
        let v4 = pseudo_v4(&[192, 168, 0, 1], &[10, 0, 0, 2], 6, 1480);
        assert_eq!(v4.fold(), reference(&[192, 168, 0, 1, 10, 0, 0, 2, 0, 6, 0x05, 0xc8]));
        let src: [u8; 16] = core::array::from_fn(|i| i as u8);
        let dst: [u8; 16] = core::array::from_fn(|i| 0xf0 | i as u8);
        let mut data = [src.as_slice(), dst.as_slice()].concat();
        data.extend_from_slice(&[0, 1, 0x23, 0x45, 0, 0, 0, 17]);
        assert_eq!(pseudo_v6(&src, &dst, 17, 0x12345).fold(), reference(&data));
    }

    #[test]
    fn large_inputs_on_every_path() {
        let data: Vec<u8> = (0..70_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        for len in [0, 1, 63, 64, 65, 127, 128, 1500, 9000, 65_535, 70_000] {
            assert_eq!(Sum::ZERO.bytes(&data[..len]).fold(), reference(&data[..len]), "length {len}");
            assert_eq!(fold64(scalar::sum(&data[..len])), fold64(native(&data[..len])), "length {len}");
            let mut copied = vec![0u8; len];
            assert_eq!(copy(&mut copied, &data[..len]).fold(), reference(&data[..len]));
            assert_eq!(copied, &data[..len]);
        }
        let ones = vec![0xffu8; 65_536];
        assert_eq!(Sum::ZERO.bytes(&ones).fold(), 0xffff);
    }

    proptest! {
        #[test]
        fn matches_the_reference(data in proptest::collection::vec(any::<u8>(), 0..4096), skip in 0usize..16) {
            let data = &data[skip.min(data.len())..];
            prop_assert_eq!(Sum::ZERO.bytes(data).fold(), reference(data));
        }

        #[test]
        fn splitting_anywhere_gives_the_same_sum(data in proptest::collection::vec(any::<u8>(), 0..2048), cuts in proptest::collection::vec(any::<usize>(), 0..6)) {
            let mut cuts: Vec<usize> = cuts.into_iter().map(|cut| cut % (data.len() + 1)).collect();
            cuts.sort_unstable();
            let mut sum = Sum::ZERO;
            let mut start = 0;
            for cut in cuts.into_iter().chain([data.len()]) {
                sum = sum.bytes(&data[start..cut]);
                start = cut;
            }
            prop_assert_eq!(sum.fold(), reference(&data));
        }

        #[test]
        fn a_word_adds_what_its_two_bytes_add_wherever_the_sum_is(
            data in proptest::collection::vec(any::<u8>(), 0..64),
            cut in any::<usize>(),
            value in any::<u16>(),
        ) {
            let cut = cut % (data.len() + 1);
            let worded = Sum::ZERO.bytes(&data[..cut]).word(value).bytes(&data[cut..]);
            let whole = [&data[..cut], &value.to_be_bytes()[..], &data[cut..]].concat();
            prop_assert_eq!(worded.fold(), reference(&whole));
        }

        #[test]
        fn combining_sums_of_pieces(data in proptest::collection::vec(any::<u8>(), 0..2048), cut in any::<usize>()) {
            let cut = cut % (data.len() + 1);
            let combined = Sum::ZERO.bytes(&data[..cut]).combine(Sum::ZERO.bytes(&data[cut..]));
            prop_assert_eq!(combined.fold(), reference(&data));
        }

        #[test]
        fn copying_sums_the_source(data in proptest::collection::vec(any::<u8>(), 0..4096), skip in 0usize..16) {
            let data = &data[skip.min(data.len())..];
            let mut out = vec![0u8; data.len() + 7];
            let target = &mut out[3..3 + data.len()];
            prop_assert_eq!(copy(target, data).fold(), reference(data));
            prop_assert_eq!(&*target, data);
        }
    }
}
