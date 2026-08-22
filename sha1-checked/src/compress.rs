use crate::{BLOCK_SIZE, DetectionState, ubc_check::Testt};

mod backend;
mod soft;
use backend::Backend;
use soft::{compression_w, recompression_step, xor};

#[inline]
pub(crate) fn compress(
    state: &mut [u32; 5],
    ctx: &mut DetectionState,
    blocks: &[[u8; BLOCK_SIZE]],
) {
    let mut block_u32 = [0u32; BLOCK_SIZE / 4];
    let backend = Backend::new();

    for block in blocks.iter() {
        ctx.ihv1.copy_from_slice(&*state);

        for (o, chunk) in block_u32.iter_mut().zip(block.chunks_exact(4)) {
            *o = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        let DetectionState {
            m1,
            state_58,
            state_65,
            ..
        } = ctx;

        backend.compress(state, block, &block_u32, m1, state_58, state_65);

        let ubc_mask = if ctx.ubc_check {
            crate::ubc_check::ubc_check(&ctx.m1)
        } else {
            0xFFFFFFFF
        };

        if ubc_mask != 0 {
            let DetectionState {
                m1,
                state_58,
                state_65,
                ihv1,
                ..
            } = ctx;
            backend.ensure_states(ihv1, state, &block_u32, m1, state_58, state_65);

            let mut ihvtmp = [0u32; 5];
            for dv_type in &crate::ubc_check::SHA1_DVS {
                if ubc_mask & (1 << dv_type.maskb) != 0 {
                    for ((m2, m1), dm) in
                        ctx.m2.iter_mut().zip(ctx.m1.iter()).zip(dv_type.dm.iter())
                    {
                        *m2 = m1 ^ dm;
                    }
                    let DetectionState {
                        ihv2,
                        m2,
                        state_58,
                        state_65,
                        ..
                    } = ctx;

                    recompression_step(
                        dv_type.testt,
                        ihv2,
                        &mut ihvtmp,
                        m2,
                        match dv_type.testt {
                            Testt::T58 => state_58,
                            Testt::T65 => state_65,
                        },
                    );

                    // to verify SHA-1 collision detection code with collisions for reduced-step SHA-1
                    if (0 == xor(&ihvtmp, &*state))
                        || (ctx.reduced_round_collision && 0 == xor(&ctx.ihv1, &ctx.ihv2))
                    {
                        ctx.found_collision = true;

                        if ctx.safe_hash {
                            compression_w(state, &ctx.m1);
                            compression_w(state, &ctx.m1);
                        }
                        break;
                    }
                }
            }
        }
    }
}

const SHA1_PADDING: [u8; 64] = [
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

#[inline]
pub(super) fn finalize(
    state: &mut [u32; 5],
    total: u64,
    last_block: &[u8],
    ctx: &mut DetectionState,
) {
    let mut total = total + last_block.len() as u64;
    let last = last_block.len();
    let needs_two_blocks = last >= 56;

    let mut buffer = [0u8; BLOCK_SIZE];
    buffer[..last].copy_from_slice(last_block);
    let left = BLOCK_SIZE - last;

    if needs_two_blocks {
        let padn = 120 - last;
        let (pad0, pad1) = SHA1_PADDING[..padn].split_at(left);
        buffer[last..].copy_from_slice(pad0);
        compress(state, ctx, &[buffer]);
        buffer[..pad1.len()].copy_from_slice(pad1);
    } else {
        let padn = 56 - last;
        buffer[last..56].copy_from_slice(&SHA1_PADDING[..padn]);
    }

    total <<= 3;

    buffer[56] = (total >> 56) as u8;
    buffer[57] = (total >> 48) as u8;
    buffer[58] = (total >> 40) as u8;
    buffer[59] = (total >> 32) as u8;
    buffer[60] = (total >> 24) as u8;
    buffer[61] = (total >> 16) as u8;
    buffer[62] = (total >> 8) as u8;
    buffer[63] = total as u8;

    compress(state, ctx, &[buffer]);
}
