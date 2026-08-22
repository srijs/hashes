//! Selects between the hardware and scalar SHA-1 compression implementations.

use crate::BLOCK_SIZE;
use crate::compress::soft::compression_states;

cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod x86_sha;
        cpufeatures::new!(hwcap, "sha", "sse2", "ssse3", "sse4.1");
    } else if #[cfg(target_arch = "aarch64")] {
        mod aarch64_sha2;
        cpufeatures::new!(hwcap, "sha2");
    }
}

enum Repr {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    X86Sha,
    #[cfg(target_arch = "aarch64")]
    Aarch64Sha2,
    Scalar,
}

/// Which implementation computes a block's digest, decided once by
/// [`Backend::new`] via cpu feature detection.
pub(super) struct Backend(Repr);

impl Backend {
    pub(super) fn new() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                if hwcap::get() {
                    return Self(Repr::X86Sha);
                }
            } else if #[cfg(target_arch = "aarch64")] {
                if hwcap::get() {
                    return Self(Repr::Aarch64Sha2);
                }
            }
        }
        Self(Repr::Scalar)
    }

    /// Digest `block` into `state`, writing the checker's input to `m1`.
    ///
    /// Depending on backend, may or may not fill in `state_58`/`state_65` too;
    /// call [`ensure_states`](Self::ensure_states) before reading them.
    pub(super) fn compress(
        &self,
        state: &mut [u32; 5],
        block: &[u8; BLOCK_SIZE],
        block_u32: &[u32; BLOCK_SIZE / 4],
        m1: &mut [u32; 80],
        state_58: &mut [u32; 5],
        state_65: &mut [u32; 5],
    ) {
        match self.0 {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Repr::X86Sha => {
                // SAFETY: `Repr::X86Sha` implies `hwcap::get()` was checked.
                unsafe { x86_sha::compress_spill(state, block, m1) };
            }
            #[cfg(target_arch = "aarch64")]
            Repr::Aarch64Sha2 => {
                // SAFETY: `Repr::Aarch64Sha2` implies `hwcap::get()` was checked.
                unsafe { aarch64_sha2::compress_spill(state, block, m1) };
            }
            Repr::Scalar => {
                let _ = block; // only the hardware paths need it
                compression_states(state, block_u32, m1, state_58, state_65);
            }
        }
    }

    /// Make sure `state_58`/`state_65` reflect this block, recomputing them
    /// via the scalar path if needed.
    pub(super) fn ensure_states(
        &self,
        ihv_before: &[u32; 5],
        state: &[u32; 5],
        block_u32: &[u32; BLOCK_SIZE / 4],
        m1: &mut [u32; 80],
        state_58: &mut [u32; 5],
        state_65: &mut [u32; 5],
    ) {
        if matches!(self.0, Repr::Scalar) {
            return;
        }
        let mut replayed = *ihv_before;
        compression_states(&mut replayed, block_u32, m1, state_58, state_65);
        debug_assert_eq!(replayed, *state, "hardware and scalar compression diverged");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn hardware_agrees_with_scalar_compression() {
        let hardware = Backend::new();
        let is_hardware = match hardware.0 {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Repr::X86Sha => true,
            #[cfg(target_arch = "aarch64")]
            Repr::Aarch64Sha2 => true,
            Repr::Scalar => false,
        };
        if !is_hardware {
            return;
        }

        let mut seed = 0x0BAD_C0DE_DEAD_BEEF;
        for _ in 0..2_000 {
            let block: [u8; BLOCK_SIZE] =
                core::array::from_fn(|_| (xorshift(&mut seed) >> 24) as u8);
            let ihv: [u32; 5] = core::array::from_fn(|_| xorshift(&mut seed) as u32);

            let mut block_u32 = [0u32; 16];
            for (word, chunk) in block_u32.iter_mut().zip(block.chunks_exact(4)) {
                *word = u32::from_be_bytes(chunk.try_into().unwrap());
            }

            let (mut hw_state, mut hw_w) = (ihv, [0u32; 80]);
            let (mut hw_s58, mut hw_s65) = ([0u32; 5], [0u32; 5]);
            hardware.compress(
                &mut hw_state,
                &block,
                &block_u32,
                &mut hw_w,
                &mut hw_s58,
                &mut hw_s65,
            );

            let mut sc_state = ihv;
            let (mut sc_w, mut s58, mut s65) = ([0u32; 80], [0u32; 5], [0u32; 5]);
            Backend(Repr::Scalar).compress(
                &mut sc_state,
                &block,
                &block_u32,
                &mut sc_w,
                &mut s58,
                &mut s65,
            );

            assert_eq!(hw_state, sc_state, "digest diverged");
            assert_eq!(hw_w, sc_w, "schedule diverged");

            // Independent of the scalar round macros, so a shared bug can't hide.
            let mut want = [0u32; 80];
            want[..16].copy_from_slice(&block_u32);
            for t in 16..80 {
                want[t] = (want[t - 3] ^ want[t - 8] ^ want[t - 14] ^ want[t - 16]).rotate_left(1);
            }
            assert_eq!(hw_w, want, "schedule is not the standard expansion");
        }
    }
}
