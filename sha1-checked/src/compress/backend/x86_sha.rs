//! SHA-1 `x86`/`x86_64` backend, spilling the message schedule alongside the
//! digest.

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("x86_sha backend can be used only on x86 and x86_64 target arches");

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

const REVERSE: i32 = 0b00011011; // used throughout to convert from SHA-NI lane order

macro_rules! rounds4 {
    ($h0:ident, $h1:ident, $wk:expr, $i:expr) => {
        _mm_sha1rnds4_epu32($h0, _mm_sha1nexte_epu32($h1, $wk), $i)
    };
}

macro_rules! schedule {
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
        _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32($v0, $v1), $v2), $v3)
    };
}

macro_rules! schedule_rounds4 {
    (
        $wp:expr, $t:expr,
        $h0:ident, $h1:ident,
        $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr,
        $i:expr
    ) => {
        $w4 = schedule!($w0, $w1, $w2, $w3);
        _mm_storeu_si128($wp.add($t).cast(), _mm_shuffle_epi32($w4, REVERSE));
        $h1 = rounds4!($h0, $h1, $w4, $i);
    };
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(crate) unsafe fn compress_spill(state: &mut [u32; 5], block: &[u8; 64], w: &mut [u32; 80]) {
    #[allow(non_snake_case)]
    let MASK: __m128i = _mm_set_epi64x(0x0001_0203_0405_0607, 0x0809_0A0B_0C0D_0E0F);

    let wp = w.as_mut_ptr();
    let block_ptr: *const __m128i = block.as_ptr().cast();

    let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(0)), MASK);
    let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(1)), MASK);
    let mut w2 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(2)), MASK);
    let mut w3 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(3)), MASK);
    #[allow(clippy::needless_late_init)]
    let mut w4;

    _mm_storeu_si128(wp.add(0).cast(), _mm_shuffle_epi32(w0, REVERSE));
    _mm_storeu_si128(wp.add(4).cast(), _mm_shuffle_epi32(w1, REVERSE));
    _mm_storeu_si128(wp.add(8).cast(), _mm_shuffle_epi32(w2, REVERSE));
    _mm_storeu_si128(wp.add(12).cast(), _mm_shuffle_epi32(w3, REVERSE));

    let state_abcd = _mm_shuffle_epi32(_mm_loadu_si128(state.as_ptr().cast()), REVERSE);
    let state_e = _mm_set_epi32(state[4] as i32, 0, 0, 0);

    let mut h0 = state_abcd;
    let mut h1 = _mm_add_epi32(state_e, w0);

    // Rounds 0..20
    h1 = _mm_sha1rnds4_epu32(h0, h1, 0);
    h0 = rounds4!(h1, h0, w1, 0);
    h1 = rounds4!(h0, h1, w2, 0);
    h0 = rounds4!(h1, h0, w3, 0);
    schedule_rounds4!(wp, 16, h0, h1, w0, w1, w2, w3, w4, 0);

    // Rounds 20..40
    schedule_rounds4!(wp, 20, h1, h0, w1, w2, w3, w4, w0, 1);
    schedule_rounds4!(wp, 24, h0, h1, w2, w3, w4, w0, w1, 1);
    schedule_rounds4!(wp, 28, h1, h0, w3, w4, w0, w1, w2, 1);
    schedule_rounds4!(wp, 32, h0, h1, w4, w0, w1, w2, w3, 1);
    schedule_rounds4!(wp, 36, h1, h0, w0, w1, w2, w3, w4, 1);

    // Rounds 40..60
    schedule_rounds4!(wp, 40, h0, h1, w1, w2, w3, w4, w0, 2);
    schedule_rounds4!(wp, 44, h1, h0, w2, w3, w4, w0, w1, 2);
    schedule_rounds4!(wp, 48, h0, h1, w3, w4, w0, w1, w2, 2);
    schedule_rounds4!(wp, 52, h1, h0, w4, w0, w1, w2, w3, 2);
    schedule_rounds4!(wp, 56, h0, h1, w0, w1, w2, w3, w4, 2);

    // Rounds 60..80
    schedule_rounds4!(wp, 60, h1, h0, w1, w2, w3, w4, w0, 3);
    schedule_rounds4!(wp, 64, h0, h1, w2, w3, w4, w0, w1, 3);
    schedule_rounds4!(wp, 68, h1, h0, w3, w4, w0, w1, w2, 3);
    schedule_rounds4!(wp, 72, h0, h1, w4, w0, w1, w2, w3, 3);
    schedule_rounds4!(wp, 76, h1, h0, w0, w1, w2, w3, w4, 3);

    let state_abcd = _mm_add_epi32(state_abcd, h0);
    let state_e = _mm_sha1nexte_epu32(h1, state_e);

    let state_abcd = _mm_shuffle_epi32(state_abcd, REVERSE);
    _mm_storeu_si128(state.as_mut_ptr().cast(), state_abcd);
    state[4] = _mm_extract_epi32(state_e, 3) as u32;
}
