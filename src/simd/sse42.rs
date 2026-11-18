use crate::iter::Bytes;

#[cfg(test)]
#[target_feature(enable = "sse4.2")]
pub unsafe fn match_uri_vectored_default(bytes: &mut Bytes) {
    match_uri_vectored(bytes, crate::RequestLinePolicy::default())
}

#[target_feature(enable = "sse4.2")]
pub unsafe fn match_uri_vectored(
    bytes: &mut Bytes,
    policy: crate::RequestLinePolicy,
) {
    while bytes.as_ref().len() >= 16 {
        let advance = if policy.allow_obs_text {
            match_url_char_16_sse(bytes.as_ref())
        } else {
            match_url_ascii_char_16_sse(bytes.as_ref())
        };

        bytes.advance(advance);

        if advance != 16 {
            return;
        }
    }
    super::swar::match_uri_vectored(bytes, policy);
}

#[inline(always)]
#[allow(non_snake_case)]
unsafe fn match_url_ascii_char_16_sse(buf: &[u8]) -> usize {
    debug_assert!(buf.len() >= 16);

    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    let ptr = buf.as_ptr();

    // strict request target: %x21-%x7e only (visible ASCII)
    let LOW: __m128i = _mm_set1_epi8(0x21);
    let HIGH: __m128i = _mm_set1_epi8(0x7e);

    let dat = _mm_lddqu_si128(ptr as *const _);
    // unsigned range check: LOW <= dat <= HIGH
    let ge_low = _mm_cmpeq_epi8(_mm_max_epu8(dat, LOW), dat);
    let le_high = _mm_cmpeq_epi8(_mm_min_epu8(dat, HIGH), dat);
    let bit = _mm_and_si128(ge_low, le_high);
    let res = _mm_movemask_epi8(bit) as u16;

    res.trailing_ones() as usize
}

#[inline(always)]
#[allow(non_snake_case)]
unsafe fn match_url_char_16_sse(buf: &[u8]) -> usize {
    debug_assert!(buf.len() >= 16);

    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    let ptr = buf.as_ptr();

    // %x21-%x7e %x80-%xff
    let DEL: __m128i = _mm_set1_epi8(0x7f);
    let LOW: __m128i = _mm_set1_epi8(0x21);

    let dat = _mm_lddqu_si128(ptr as *const _);
    // unsigned comparison dat >= LOW
    let low = _mm_cmpeq_epi8(_mm_max_epu8(dat, LOW), dat);
    let del = _mm_cmpeq_epi8(dat, DEL);
    let bit = _mm_andnot_si128(del, low);
    let res = _mm_movemask_epi8(bit) as u16;

    res.trailing_ones() as usize
}

#[target_feature(enable = "sse4.2")]
pub unsafe fn match_header_value_vectored(bytes: &mut Bytes) {
    while bytes.as_ref().len() >= 16 {
        let advance = match_header_value_char_16_sse(bytes.as_ref());
        bytes.advance(advance);

       if advance != 16 {
            return;
       }
    }
    super::swar::match_header_value_vectored(bytes);
}

#[inline(always)]
#[allow(non_snake_case)]
unsafe fn match_header_value_char_16_sse(buf: &[u8]) -> usize {
    debug_assert!(buf.len() >= 16);

    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    let ptr = buf.as_ptr();

    // %x09 %x20-%x7e %x80-%xff
    let TAB: __m128i = _mm_set1_epi8(0x09);
    let DEL: __m128i = _mm_set1_epi8(0x7f);
    let LOW: __m128i = _mm_set1_epi8(0x20);

    let dat = _mm_lddqu_si128(ptr as *const _);
    // unsigned comparison dat >= LOW
    let low = _mm_cmpeq_epi8(_mm_max_epu8(dat, LOW), dat);
    let tab = _mm_cmpeq_epi8(dat, TAB);
    let del = _mm_cmpeq_epi8(dat, DEL);
    let bit = _mm_andnot_si128(del, _mm_or_si128(low, tab));
    let res = _mm_movemask_epi8(bit) as u16;

    res.trailing_ones() as usize
}

#[test]
fn sse_code_matches_uri_chars_table() {
    if !is_x86_feature_detected!("sse4.2") {
        return;
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    unsafe {
        assert!(byte_is_allowed(b'_', match_uri_vectored_default));

        for (b, allowed) in crate::URI_MAP_STRICT.iter().cloned().enumerate() {
            assert_eq!(
                byte_is_allowed(b as u8, match_uri_vectored_default), allowed,
                "byte_is_allowed({:?}) should be {:?}", b, allowed,
            );
        }
    }
}

#[test]
fn sse_code_matches_obs_text_uri_chars_table() {
    if !is_x86_feature_detected!("sse4.2") {
        return;
    }

    let policy = crate::RequestLinePolicy {
        allow_multiple_spaces: false,
        allow_obs_text: true,
    };

    #[allow(clippy::undocumented_unsafe_blocks)]
    unsafe {
        for (b, allowed) in crate::URI_MAP_OBS_TEXT.iter().cloned().enumerate() {
            assert_eq!(
                byte_is_allowed_policy(b as u8, policy, match_uri_vectored),
                allowed,
                "byte_is_allowed({:?}) should be {:?}",
                b,
                allowed,
            );
        }
    }
}

#[test]
fn sse_code_matches_header_value_chars_table() {
    if !is_x86_feature_detected!("sse4.2") {
        return;
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    unsafe {
        assert!(byte_is_allowed(b'_', match_header_value_vectored));

        for (b, allowed) in crate::HEADER_VALUE_MAP.iter().cloned().enumerate() {
            assert_eq!(
                byte_is_allowed(b as u8, match_header_value_vectored), allowed,
                "byte_is_allowed({:?}) should be {:?}", b, allowed,
            );
        }
    }
}

#[allow(clippy::missing_safety_doc)]
#[cfg(test)]
unsafe fn byte_is_allowed(byte: u8, f: unsafe fn(bytes: &mut Bytes<'_>)) -> bool {
    let slice = [
        b'_', b'_', b'_', b'_',
        b'_', b'_', b'_', b'_',
        b'_', b'_', byte, b'_',
        b'_', b'_', b'_', b'_',
    ];
    let mut bytes = Bytes::new(&slice);

    f(&mut bytes);

    match bytes.pos() {
        16 => true,
        10 => false,
        _ => unreachable!(),
    }
}

#[cfg(test)]
unsafe fn byte_is_allowed_policy(
    byte: u8,
    policy: crate::RequestLinePolicy,
    f: unsafe fn(bytes: &mut Bytes<'_>, crate::RequestLinePolicy),
) -> bool {
    let slice = [
        b'_', b'_', b'_', b'_',
        b'_', b'_', b'_', b'_',
        b'_', b'_', byte, b'_',
        b'_', b'_', b'_', b'_',
    ];
    let mut bytes = Bytes::new(&slice);

    f(&mut bytes, policy);

    match bytes.pos() {
        16 => true,
        10 => false,
        _ => unreachable!(),
    }
}
