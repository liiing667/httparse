/// SWAR: SIMD Within A Register
/// SIMD validator backend that validates register-sized chunks of data at a time.
use crate::{is_header_name_token, is_header_value_token, is_uri_token, Bytes};

// Adapt block-size to match native register size, i.e: 32bit => 4, 64bit => 8
const BLOCK_SIZE: usize = core::mem::size_of::<usize>();
type ByteBlock = [u8; BLOCK_SIZE];

#[inline]
pub fn match_uri_vectored(bytes: &mut Bytes) {
    loop {
        if let Some(bytes8) = bytes.peek_n::<BLOCK_SIZE>() {
            let n = match_uri_char_8_swar(bytes8);
            // SAFETY: using peek_n to retrieve the bytes ensures that there are at least n more bytes
            // in `bytes`, so calling `advance(n)` is safe.
            unsafe {
                bytes.advance(n);
            }
            if n == BLOCK_SIZE {
                continue;
            }
        }
        if let Some(b) = bytes.peek() {
            if is_uri_token(b) {
                // SAFETY: using peek to retrieve the byte ensures that there is at least 1 more byte
                // in bytes, so calling advance is safe.
                unsafe {
                    bytes.advance(1);
                }
                continue;
            }
        }
        break;
    }
}

#[inline]
pub fn match_header_value_vectored(bytes: &mut Bytes) {
    loop {
        if let Some(bytes8) = bytes.peek_n::<BLOCK_SIZE>() {
            let n = match_header_value_char_8_swar(bytes8);
            // SAFETY: using peek_n to retrieve the bytes ensures that there are at least n more bytes
            // in `bytes`, so calling `advance(n)` is safe.
            unsafe {
                bytes.advance(n);
            }
            if n == BLOCK_SIZE {
                continue;
            }
        }
        if let Some(b) = bytes.peek() {
            if is_header_value_token(b) {
                // SAFETY: using peek to retrieve the byte ensures that there is at least 1 more byte
                // in bytes, so calling advance is safe.
                unsafe {
                    bytes.advance(1);
                }
                continue;
            }
        }
        break;
    }
}

#[inline]
pub fn match_header_name_vectored(bytes: &mut Bytes) {
    while let Some(block) = bytes.peek_n::<BLOCK_SIZE>() {
        let n = match_block(is_header_name_token, block);
        // SAFETY: using peek_n to retrieve the bytes ensures that there are at least n more bytes
        // in `bytes`, so calling `advance(n)` is safe.
        unsafe {
            bytes.advance(n);
        }
        if n != BLOCK_SIZE {
            return;
        }
    }
    // SAFETY: match_tail processes at most the remaining data in `bytes`. advances `bytes` to the
    // end, but no further.
    unsafe { bytes.advance(match_tail(is_header_name_token, bytes.as_ref())) };
}

// Matches "tail", i.e: when we have <BLOCK_SIZE bytes in the buffer, should be uncommon
#[cold]
#[inline]
fn match_tail(f: impl Fn(u8) -> bool, bytes: &[u8]) -> usize {
    for (i, &b) in bytes.iter().enumerate() {
        if !f(b) {
            return i;
        }
    }
    bytes.len()
}

// Naive fallback block matcher
#[inline(always)]
fn match_block(f: impl Fn(u8) -> bool, block: ByteBlock) -> usize {
    for (i, &b) in block.iter().enumerate() {
        if !f(b) {
            return i;
        }
    }
    BLOCK_SIZE
}

// creates a u64 whose bytes are each equal to b
const fn uniform_block(b: u8) -> usize {
    // The SWAR arithmetic below relies on subtraction borrows propagating
    // from a byte toward the *next* byte.  That only matches the memory order
    // of the block on a little-endian host, where the first byte is the least
    // significant.  Feeding the block through the little-endian
    // (de)serialization everywhere keeps the two scan paths (SWAR and the
    // vector backends) equivalent on big-endian targets as well.
    usize::from_le_bytes([b; BLOCK_SIZE])
}

// A byte-wise range-check on an entire word/block,
// ensuring all bytes in the word satisfy `33 <= (x != 127) <= 255`
#[inline]
fn match_uri_char_8_swar(block: ByteBlock) -> usize {
    // 33 <= (x != 127) <= 255
    const M: u8 = 0x21;
    // uniform block full of exclamation mark (!) (33).
    const BM: usize = uniform_block(M);
    // uniform block full of 1.
    const ONE: usize = uniform_block(0x01);
    // uniform block full of DEL (127).
    const DEL: usize = uniform_block(0x7f);
    // uniform block full of 128.
    const M128: usize = uniform_block(128);

    // Interpret the block as a little-endian word so that borrow/carry flows
    // between adjacent bytes follow their order in the caller's buffer.
    let x = usize::from_le_bytes(block);
    let lt = x.wrapping_sub(BM) & !x; // <= m

    let xor_del = x ^ DEL;
    let eq_del = xor_del.wrapping_sub(ONE) & !xor_del; // == DEL

    offsetnz((lt | eq_del) & M128)
}

// A byte-wise range-check on an entire word/block,
// ensuring all bytes in the word satisfy `32 <= (x != 127) <= 255`
#[inline]
fn match_header_value_char_8_swar(block: ByteBlock) -> usize {
    // 32 <= (x != 127) <= 255
    const M: u8 = 0x20;
    // uniform block full of exclamation mark (!) (33).
    const BM: usize = uniform_block(M);
    // uniform block full of 1.
    const ONE: usize = uniform_block(0x01);
    // uniform block full of DEL (127).
    const DEL: usize = uniform_block(0x7f);
    // uniform block full of 128.
    const M128: usize = uniform_block(128);

    // See `match_uri_char_8_swar` for why the block is read as little-endian.
    let x = usize::from_le_bytes(block);
    let lt = x.wrapping_sub(BM) & !x; // <= m

    let xor_del = x ^ DEL;
    let eq_del = xor_del.wrapping_sub(ONE) & !xor_del; // == DEL

    offsetnz((lt | eq_del) & M128)
}

/// Check block to find offset of first non-zero byte
// NOTE: Curiously `block.trailing_zeros() >> 3` appears to be slower, maybe revisit
#[inline]
fn offsetnz(block: usize) -> usize {
    // fast path optimistic case (common for long valid sequences)
    if block == 0 {
        return BLOCK_SIZE;
    }

    // perf: rust will unroll this loop
    for (i, b) in block.to_le_bytes().iter().copied().enumerate() {
        if b != 0 {
            return i;
        }
    }
    unreachable!()
}

#[test]
fn test_is_header_value_block() {
    let is_header_value_block = |b| match_header_value_char_8_swar(b) == BLOCK_SIZE;

    // 0..32 => false
    for b in 0..32_u8 {
        assert!(!is_header_value_block([b; BLOCK_SIZE]), "b={}", b);
    }
    // 32..=126 => true
    for b in 32..=126_u8 {
        assert!(is_header_value_block([b; BLOCK_SIZE]), "b={}", b);
    }
    // 127 => false
    assert!(!is_header_value_block([b'\x7F'; BLOCK_SIZE]), "b={}", b'\x7F');
    // 128..=255 => true
    for b in 128..=255_u8 {
        assert!(is_header_value_block([b; BLOCK_SIZE]), "b={}", b);
    }


    #[cfg(target_pointer_width = "64")]
    {
        // A few sanity checks on non-uniform bytes for safe-measure
        assert!(!is_header_value_block(*b"foo.com\n"));
        assert!(!is_header_value_block(*b"o.com\r\nU"));
    }
}

#[test]
fn test_is_uri_block() {
    let is_uri_block = |b| match_uri_char_8_swar(b) == BLOCK_SIZE;

    // 0..33 => false
    for b in 0..33_u8 {
        assert!(!is_uri_block([b; BLOCK_SIZE]), "b={}", b);
    }
    // 33..=126 => true
    for b in 33..=126_u8 {
        assert!(is_uri_block([b; BLOCK_SIZE]), "b={}", b);
    }
    // 127 => false
    assert!(!is_uri_block([b'\x7F'; BLOCK_SIZE]), "b={}", b'\x7F');
    // 128..=255 => true
    for b in 128..=255_u8 {
        assert!(is_uri_block([b; BLOCK_SIZE]), "b={}", b);
    }
}

#[test]
fn test_offsetnz() {
    let seq = [0_u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        let mut seq = seq;
        seq[i] = 1;
        // `offsetnz` indexes bytes in little-endian (memory) order, so build
        // the probe word the same way to stay correct on every endianness.
        let x = usize::from_le_bytes(seq);
        assert_eq!(offsetnz(x), i);
    }
}

// The SWAR word math uses subtraction, whose borrow can spill into a
// neighboring byte.  On a big-endian host that borrow points toward an
// *earlier* byte in the caller's buffer, which previously made the generic
// scan reject bytes that the vector backends (SSE4.2/AVX2/NEON) accept.
// Exhaustively checking every adjacent byte pair keeps both scan paths in
// sync regardless of target endianness.
#[test]
fn test_uri_block_matches_scalar_for_all_byte_pairs() {
    for first in 0..=u8::MAX {
        for second in 0..=u8::MAX {
            let mut block = [b'a'; BLOCK_SIZE];
            block[0] = first;
            block[1] = second;

            let expected = block
                .iter()
                .position(|&b| !is_uri_token(b))
                .unwrap_or(BLOCK_SIZE);

            assert_eq!(
                match_uri_char_8_swar(block),
                expected,
                "first={first:#x}, second={second:#x}",
            );
        }
    }
}

#[test]
fn test_header_value_block_matches_scalar_for_all_byte_pairs() {
    for first in 0..=u8::MAX {
        for second in 0..=u8::MAX {
            let mut block = [b'a'; BLOCK_SIZE];
            block[0] = first;
            block[1] = second;

            // TAB (0x09) is only recognized by the scalar tail in
            // `match_header_value_vectored`, so the block matcher treats it
            // like every other byte below the lower bound.
            let block_predicate = |b: u8| b >= 0x20 && b != 0x7F;
            let expected = block
                .iter()
                .position(|&b| !block_predicate(b))
                .unwrap_or(BLOCK_SIZE);

            assert_eq!(
                match_header_value_char_8_swar(block),
                expected,
                "first={first:#x}, second={second:#x}",
            );
        }
    }
}

// End-to-end guarantee: a URI containing a low/control byte later in the
// block must stop exactly at that byte, never at an earlier valid byte.
// This is the concrete divergence reported between vector and generic scans.
#[test]
fn test_uri_vectored_does_not_falsely_reject_earlier_valid_bytes() {
    // First byte is the lowest valid URI char (`!` = 0x21); the second is
    // invalid.  Big-endian SWAR used to report offset 0 instead of 1 here.
    let mut block = [b'a'; BLOCK_SIZE * 2 + 2];
    block[0] = b'!';
    block[1] = b' ';

    let mut bytes = crate::Bytes::new(&block);
    match_uri_vectored(&mut bytes);
    assert_eq!(bytes.pos(), 1);
}
