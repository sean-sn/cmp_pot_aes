// https://github.com/subspace/rust-aes-proofs/blob/master/src/aes_low_level/aes_ni/expand.rs
use core::arch::x86_64::*;
use core::mem;

macro_rules! expand_round {
    ($enc_keys:expr, $dec_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = _mm_load_si128($enc_keys.as_ptr().offset($pos - 1));
        let mut t2;
        let mut t3;

        t2 = _mm_aeskeygenassist_si128(t1, $round);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t3 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128(t3, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128(t3, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t1 = _mm_xor_si128(t1, t2);

        _mm_store_si128($enc_keys.as_mut_ptr().offset($pos), t1);
        let t1 = if $pos != 10 { _mm_aesimc_si128(t1) } else { t1 };
        _mm_store_si128($dec_keys.as_mut_ptr().offset($pos), t1);
    };
}

#[inline(always)]
pub fn expand(key: &[u8; 16]) -> ([__m128i; 11], [__m128i; 11]) {
    unsafe {
        let mut enc_keys: [__m128i; 11] = mem::zeroed();
        let mut dec_keys: [__m128i; 11] = mem::zeroed();

        // Safety: `loadu` supports unaligned loads
        #[allow(clippy::cast_ptr_alignment)]
        let k = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        _mm_store_si128(enc_keys.as_mut_ptr(), k);
        _mm_store_si128(dec_keys.as_mut_ptr(), k);

        expand_round!(enc_keys, dec_keys, 1, 0x01);
        expand_round!(enc_keys, dec_keys, 2, 0x02);
        expand_round!(enc_keys, dec_keys, 3, 0x04);
        expand_round!(enc_keys, dec_keys, 4, 0x08);
        expand_round!(enc_keys, dec_keys, 5, 0x10);
        expand_round!(enc_keys, dec_keys, 6, 0x20);
        expand_round!(enc_keys, dec_keys, 7, 0x40);
        expand_round!(enc_keys, dec_keys, 8, 0x80);
        expand_round!(enc_keys, dec_keys, 9, 0x1B);
        expand_round!(enc_keys, dec_keys, 10, 0x36);

        (enc_keys, dec_keys)
    }
}

// https://github.com/subspace/rust-aes-proofs/blob/master/src/aes_low_level/aes_ni.rs
/*
macro_rules! aes128_load {
    ($var:expr) => {{
        use core::arch::x86_64::*;

        _mm_loadu_si128($var.as_ptr() as *const __m128i)
    }};
}
*/

pub fn pot_prove_low_level(
    keys_reg: [__m128i; 11],
    mut block_reg: __m128i,
    inner_iterations: usize,
) -> __m128i {
    unsafe {
        for _ in 0..inner_iterations {
            block_reg = _mm_xor_si128(block_reg, keys_reg[0]);
            block_reg = _mm_aesenc_si128(block_reg, keys_reg[1]);
            block_reg = _mm_aesenc_si128(block_reg, keys_reg[2]);
            block_reg = _mm_aesenc_si128(block_reg, keys_reg[3]);
            block_reg = _mm_aesenc_si128(block_reg, keys_reg[4]);
            block_reg = _mm_aesenc_si128(block_reg, keys_reg[5]);
            block_reg = _mm_aesenc_si128(block_reg, keys_reg[6]);
            block_reg = _mm_aesenc_si128(block_reg, keys_reg[7]);
            block_reg = _mm_aesenc_si128(block_reg, keys_reg[8]);
            block_reg = _mm_aesenc_si128(block_reg, keys_reg[9]);

            block_reg = _mm_aesenclast_si128(block_reg, keys_reg[10]);
        }
    }

    block_reg
}

// https://github.com/subspace/rust-aes-proofs/blob/master/src/pot/test_data.rs
pub const SEED: [u8; 16] = [
    0xd6, 0x66, 0xcc, 0xd8, 0xd5, 0x93, 0xc2, 0x3d, 0xa8, 0xdb, 0x6b, 0x5b, 0x14, 0x13, 0xb1, 0x3a,
];

pub const ID: [u8; 16] = [
    0x9a, 0x84, 0x94, 0x0f, 0xfe, 0xf5, 0xb0, 0xd7, 0x01, 0x99, 0xfc, 0x67, 0xf4, 0x6e, 0xa2, 0x7a,
];

pub fn pot_prove_low_level_asm(
    keys_reg: [__m128i; 11],
    mut block_asm: __m128i,
    iterations: usize,
) -> __m128i {
    unsafe {
        asm!(
             //"vmovdqu     xmm11, [rsi + 0*16]",   // Input block
             // Move key schedule into registers
             "vmovdqu     xmm0,  [rdi + 0*16]",
             "vmovdqu     xmm1,  [rdi + 1*16]",
             "vmovdqu     xmm2,  [rdi + 2*16]",
             "vmovdqu     xmm3,  [rdi + 3*16]",
             "vmovdqu     xmm4,  [rdi + 4*16]",
             "vmovdqu     xmm5,  [rdi + 5*16]",
             "vmovdqu     xmm6,  [rdi + 6*16]",
             "vmovdqu     xmm7,  [rdi + 7*16]",
             "vmovdqu     xmm8,  [rdi + 8*16]",
             "vmovdqu     xmm9,  [rdi + 9*16]",
             "vmovdqu     xmm10, [rdi + 10*16]",
             "vpxor       xmm12, xmm0, xmm10",  // Key 0 ^ key 10
             // Start AES block encryption
             "vpxor       xmm11, xmm11, xmm0",  // Input ^ Key 0
             "sub         edx, 1",              // Subtract one from counter
             "jz          3f",
             "2:",
             "vaesenc     xmm11, xmm11, xmm1",  // Round 0
             "vaesenc     xmm11, xmm11, xmm2",  // Round 1
             "vaesenc     xmm11, xmm11, xmm3",  // Round 2
             "vaesenc     xmm11, xmm11, xmm4",  // Round 3
             "vaesenc     xmm11, xmm11, xmm5",  // Round 4
             "vaesenc     xmm11, xmm11, xmm6",  // Round 5
             "vaesenc     xmm11, xmm11, xmm7",  // Round 6
             "vaesenc     xmm11, xmm11, xmm8",  // Round 7
             "vaesenc     xmm11, xmm11, xmm9",  // Round 8
             "vaesenclast xmm11, xmm11, xmm12", // Round 9
             "dec         edx",                 // Decrement loop counter
             "jnz         2b",
             "3:",
             // Final Iteration
             "vaesenc     xmm11, xmm11, xmm1",  // Round 0
             "vaesenc     xmm11, xmm11, xmm2",  // Round 1
             "vaesenc     xmm11, xmm11, xmm3",  // Round 2
             "vaesenc     xmm11, xmm11, xmm4",  // Round 3
             "vaesenc     xmm11, xmm11, xmm5",  // Round 4
             "vaesenc     xmm11, xmm11, xmm6",  // Round 5
             "vaesenc     xmm11, xmm11, xmm7",  // Round 6
             "vaesenc     xmm11, xmm11, xmm8",  // Round 7
             "vaesenc     xmm11, xmm11, xmm9",  // Round 8
             "vaesenclast xmm11, xmm11, xmm10", // Round 9
             in("rdi") keys_reg.as_ptr(),
             //in("rsi") block_asm.as_ptr(),
             in("edx") iterations,
             out("xmm0") _, // to show clobbered use out("xmm0") _,
             out("xmm1") _,
             out("xmm2") _,
             out("xmm3") _,
             out("xmm4") _,
             out("xmm5") _,
             out("xmm6") _,
             out("xmm7") _,
             out("xmm8") _,
             out("xmm9") _,
             out("xmm10") _,
             inout("xmm11") block_asm,
             out("xmm12") _,
        );
    }
    block_asm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let iterations = 1_000_000;
        let (keys_enc, _) = expand(&ID);
        let mut block_reg = unsafe { _mm_loadu_si128(SEED.as_ptr() as *const __m128i) };
        block_reg = pot_prove_low_level(keys_enc, block_reg, iterations);
        println!("{:x?}", block_reg);
    
        let mut block_asm = unsafe { _mm_loadu_si128(SEED.as_ptr() as *const __m128i) };
        block_asm = pot_prove_low_level_asm(keys_enc, block_asm, iterations);
        println!("{:x?}", block_asm);

        unsafe {
            let cmp = _mm_cmpeq_epi64(block_reg, block_asm);
            let tst = _mm_movemask_epi8(cmp);
            assert_eq!(tst, 0xFFFF);
        }
    }
}
