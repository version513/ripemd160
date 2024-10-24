/// RIPEMD-160 is a 160-bit cryptographic hash function,
/// designed by Hans Dobbertin, Antoon Bosselaers, and Bart Preneel.
/// SPEC: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
///
/// This package also provides optimization for most common input lenght: 32 bytes.
/// See: [`pad_input`]
///
#[cfg(test)]
mod tests;

use alexandria_data_structures::byte_appender::ByteAppender;
use alexandria_data_structures::array_ext::ArrayTraitExt;
use alexandria_data_structures::byte_reader::ByteReader;
use alexandria_math::U32BitRotate;
use core::num::traits::Bounded;
use core::num::traits::WrappingAdd;

const POW_2_29: u32 = 536870912;
const CHUNK_SIZE: usize = 16;


fn init_state() -> Span<u32> {
    array![0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0].span()
}

pub fn ripemd160(mut input: Array<u8>) -> Array<u8> {
    let (input, mut n_chunks) = pad_input(input);
    let state = init_state();
    let first_run = true;

    let out = {
        if n_chunks == 1 {
            ripemd160_compress(input, state, first_run)
        } else {
            let mut i = 0;
            n_chunks -= 1;
            let mut out = ripemd160_compress(input.slice(i, CHUNK_SIZE), state, first_run);

            // explicit change `first_run` into `false` due to state recalculation
            // of each next [`ripemd160_compress`] invocation.

            while n_chunks != 0 {
                i += 1;
                n_chunks -= 1;
                out = ripemd160_compress(input.slice(CHUNK_SIZE * i, CHUNK_SIZE), out, false);
            };
            out
        }
    };

    u32_array_to_u8_array_le(out)
}

fn ripemd160_compress(data: Span<u32>, s: Span<u32>, first_run: bool) -> Span<u32> {
    let (aa, aaa, bb, bbb, cc, ccc, dd, ddd, ee, eee) = {
        if first_run {
            // Init known state if the first run
            (*s[0], *s[0], *s[1], *s[1], *s[2], *s[2], *s[3], *s[3], *s[4], *s[4])
        } else {
            // Compute state for each next chunk
            let max_u32: NonZero<u32> = Bounded::<u32>::MAX.try_into().expect('Not a zero');
            let (_, aa) = DivRem::div_rem(*s[0], max_u32);
            let (_, bb) = DivRem::div_rem(*s[1], max_u32);
            let (_, cc) = DivRem::div_rem(*s[2], max_u32);
            let (_, dd) = DivRem::div_rem(*s[3], max_u32);
            let (_, ee) = DivRem::div_rem(*s[4], max_u32);
            (aa, aa, bb, bb, cc, cc, dd, dd, ee, ee)
        }
    };

    /// ROUNDS: 5 + parallel 5
    /// 16 steps each

    // round 1
    let (aa, cc) = FF(aa, bb, cc, dd, ee, *data[0], 11);
    let (ee, bb) = FF(ee, aa, bb, cc, dd, *data[1], 14);
    let (dd, aa) = FF(dd, ee, aa, bb, cc, *data[2], 15);
    let (cc, ee) = FF(cc, dd, ee, aa, bb, *data[3], 12);
    let (bb, dd) = FF(bb, cc, dd, ee, aa, *data[4], 5);
    let (aa, cc) = FF(aa, bb, cc, dd, ee, *data[5], 8);
    let (ee, bb) = FF(ee, aa, bb, cc, dd, *data[6], 7);
    let (dd, aa) = FF(dd, ee, aa, bb, cc, *data[7], 9);
    let (cc, ee) = FF(cc, dd, ee, aa, bb, *data[8], 11);
    let (bb, dd) = FF(bb, cc, dd, ee, aa, *data[9], 13);
    let (aa, cc) = FF(aa, bb, cc, dd, ee, *data[10], 14);
    let (ee, bb) = FF(ee, aa, bb, cc, dd, *data[11], 15);
    let (dd, aa) = FF(dd, ee, aa, bb, cc, *data[12], 6);
    let (cc, ee) = FF(cc, dd, ee, aa, bb, *data[13], 7);
    let (bb, dd) = FF(bb, cc, dd, ee, aa, *data[14], 9);
    let (aa, cc) = FF(aa, bb, cc, dd, ee, *data[15], 8);

    // round 2
    let (ee, bb) = GG(ee, aa, bb, cc, dd, *data[7], 7);
    let (dd, aa) = GG(dd, ee, aa, bb, cc, *data[4], 6);
    let (cc, ee) = GG(cc, dd, ee, aa, bb, *data[13], 8);
    let (bb, dd) = GG(bb, cc, dd, ee, aa, *data[1], 13);
    let (aa, cc) = GG(aa, bb, cc, dd, ee, *data[10], 11);
    let (ee, bb) = GG(ee, aa, bb, cc, dd, *data[6], 9);
    let (dd, aa) = GG(dd, ee, aa, bb, cc, *data[15], 7);
    let (cc, ee) = GG(cc, dd, ee, aa, bb, *data[3], 15);
    let (bb, dd) = GG(bb, cc, dd, ee, aa, *data[12], 7);
    let (aa, cc) = GG(aa, bb, cc, dd, ee, *data[0], 12);
    let (ee, bb) = GG(ee, aa, bb, cc, dd, *data[9], 15);
    let (dd, aa) = GG(dd, ee, aa, bb, cc, *data[5], 9);
    let (cc, ee) = GG(cc, dd, ee, aa, bb, *data[2], 11);
    let (bb, dd) = GG(bb, cc, dd, ee, aa, *data[14], 7);
    let (aa, cc) = GG(aa, bb, cc, dd, ee, *data[11], 13);
    let (ee, bb) = GG(ee, aa, bb, cc, dd, *data[8], 12);

    // round 3
    let (dd, aa) = HH(dd, ee, aa, bb, cc, *data[3], 11);
    let (cc, ee) = HH(cc, dd, ee, aa, bb, *data[10], 13);
    let (bb, dd) = HH(bb, cc, dd, ee, aa, *data[14], 6);
    let (aa, cc) = HH(aa, bb, cc, dd, ee, *data[4], 7);
    let (ee, bb) = HH(ee, aa, bb, cc, dd, *data[9], 14);
    let (dd, aa) = HH(dd, ee, aa, bb, cc, *data[15], 9);
    let (cc, ee) = HH(cc, dd, ee, aa, bb, *data[8], 13);
    let (bb, dd) = HH(bb, cc, dd, ee, aa, *data[1], 15);
    let (aa, cc) = HH(aa, bb, cc, dd, ee, *data[2], 14);
    let (ee, bb) = HH(ee, aa, bb, cc, dd, *data[7], 8);
    let (dd, aa) = HH(dd, ee, aa, bb, cc, *data[0], 13);
    let (cc, ee) = HH(cc, dd, ee, aa, bb, *data[6], 6);
    let (bb, dd) = HH(bb, cc, dd, ee, aa, *data[13], 5);
    let (aa, cc) = HH(aa, bb, cc, dd, ee, *data[11], 12);
    let (ee, bb) = HH(ee, aa, bb, cc, dd, *data[5], 7);
    let (dd, aa) = HH(dd, ee, aa, bb, cc, *data[12], 5);

    // round 4
    let (cc, ee) = II(cc, dd, ee, aa, bb, *data[1], 11);
    let (bb, dd) = II(bb, cc, dd, ee, aa, *data[9], 12);
    let (aa, cc) = II(aa, bb, cc, dd, ee, *data[11], 14);
    let (ee, bb) = II(ee, aa, bb, cc, dd, *data[10], 15);
    let (dd, aa) = II(dd, ee, aa, bb, cc, *data[0], 14);
    let (cc, ee) = II(cc, dd, ee, aa, bb, *data[8], 15);
    let (bb, dd) = II(bb, cc, dd, ee, aa, *data[12], 9);
    let (aa, cc) = II(aa, bb, cc, dd, ee, *data[4], 8);
    let (ee, bb) = II(ee, aa, bb, cc, dd, *data[13], 9);
    let (dd, aa) = II(dd, ee, aa, bb, cc, *data[3], 14);
    let (cc, ee) = II(cc, dd, ee, aa, bb, *data[7], 5);
    let (bb, dd) = II(bb, cc, dd, ee, aa, *data[15], 6);
    let (aa, cc) = II(aa, bb, cc, dd, ee, *data[14], 8);
    let (ee, bb) = II(ee, aa, bb, cc, dd, *data[5], 6);
    let (dd, aa) = II(dd, ee, aa, bb, cc, *data[6], 5);
    let (cc, ee) = II(cc, dd, ee, aa, bb, *data[2], 12);

    // round 5
    let (bb, dd) = JJ(bb, cc, dd, ee, aa, *data[4], 9);
    let (aa, cc) = JJ(aa, bb, cc, dd, ee, *data[0], 15);
    let (ee, bb) = JJ(ee, aa, bb, cc, dd, *data[5], 5);
    let (dd, aa) = JJ(dd, ee, aa, bb, cc, *data[9], 11);
    let (cc, ee) = JJ(cc, dd, ee, aa, bb, *data[7], 6);
    let (bb, dd) = JJ(bb, cc, dd, ee, aa, *data[12], 8);
    let (aa, cc) = JJ(aa, bb, cc, dd, ee, *data[2], 13);
    let (ee, bb) = JJ(ee, aa, bb, cc, dd, *data[10], 12);
    let (dd, aa) = JJ(dd, ee, aa, bb, cc, *data[14], 5);
    let (cc, ee) = JJ(cc, dd, ee, aa, bb, *data[1], 12);
    let (bb, dd) = JJ(bb, cc, dd, ee, aa, *data[3], 13);
    let (aa, cc) = JJ(aa, bb, cc, dd, ee, *data[8], 14);
    let (ee, bb) = JJ(ee, aa, bb, cc, dd, *data[11], 11);
    let (dd, aa) = JJ(dd, ee, aa, bb, cc, *data[6], 8);
    let (cc, ee) = JJ(cc, dd, ee, aa, bb, *data[15], 5);
    let (bb, dd) = JJ(bb, cc, dd, ee, aa, *data[13], 6);

    // parallel round 1
    let (aaa, ccc) = JJJ(aaa, bbb, ccc, ddd, eee, *data[5], 8);
    let (eee, bbb) = JJJ(eee, aaa, bbb, ccc, ddd, *data[14], 9);
    let (ddd, aaa) = JJJ(ddd, eee, aaa, bbb, ccc, *data[7], 9);
    let (ccc, eee) = JJJ(ccc, ddd, eee, aaa, bbb, *data[0], 11);
    let (bbb, ddd) = JJJ(bbb, ccc, ddd, eee, aaa, *data[9], 13);
    let (aaa, ccc) = JJJ(aaa, bbb, ccc, ddd, eee, *data[2], 15);
    let (eee, bbb) = JJJ(eee, aaa, bbb, ccc, ddd, *data[11], 15);
    let (ddd, aaa) = JJJ(ddd, eee, aaa, bbb, ccc, *data[4], 5);
    let (ccc, eee) = JJJ(ccc, ddd, eee, aaa, bbb, *data[13], 7);
    let (bbb, ddd) = JJJ(bbb, ccc, ddd, eee, aaa, *data[6], 7);
    let (aaa, ccc) = JJJ(aaa, bbb, ccc, ddd, eee, *data[15], 8);
    let (eee, bbb) = JJJ(eee, aaa, bbb, ccc, ddd, *data[8], 11);
    let (ddd, aaa) = JJJ(ddd, eee, aaa, bbb, ccc, *data[1], 14);
    let (ccc, eee) = JJJ(ccc, ddd, eee, aaa, bbb, *data[10], 14);
    let (bbb, ddd) = JJJ(bbb, ccc, ddd, eee, aaa, *data[3], 12);
    let (aaa, ccc) = JJJ(aaa, bbb, ccc, ddd, eee, *data[12], 6);

    // parallel round 2
    let (eee, bbb) = III(eee, aaa, bbb, ccc, ddd, *data[6], 9);
    let (ddd, aaa) = III(ddd, eee, aaa, bbb, ccc, *data[11], 13);
    let (ccc, eee) = III(ccc, ddd, eee, aaa, bbb, *data[3], 15);
    let (bbb, ddd) = III(bbb, ccc, ddd, eee, aaa, *data[7], 7);
    let (aaa, ccc) = III(aaa, bbb, ccc, ddd, eee, *data[0], 12);
    let (eee, bbb) = III(eee, aaa, bbb, ccc, ddd, *data[13], 8);
    let (ddd, aaa) = III(ddd, eee, aaa, bbb, ccc, *data[5], 9);
    let (ccc, eee) = III(ccc, ddd, eee, aaa, bbb, *data[10], 11);
    let (bbb, ddd) = III(bbb, ccc, ddd, eee, aaa, *data[14], 7);
    let (aaa, ccc) = III(aaa, bbb, ccc, ddd, eee, *data[15], 7);
    let (eee, bbb) = III(eee, aaa, bbb, ccc, ddd, *data[8], 12);
    let (ddd, aaa) = III(ddd, eee, aaa, bbb, ccc, *data[12], 7);
    let (ccc, eee) = III(ccc, ddd, eee, aaa, bbb, *data[4], 6);
    let (bbb, ddd) = III(bbb, ccc, ddd, eee, aaa, *data[9], 15);
    let (aaa, ccc) = III(aaa, bbb, ccc, ddd, eee, *data[1], 13);
    let (eee, bbb) = III(eee, aaa, bbb, ccc, ddd, *data[2], 11);

    // parallel round 3
    let (ddd, aaa) = HHH(ddd, eee, aaa, bbb, ccc, *data[15], 9);
    let (ccc, eee) = HHH(ccc, ddd, eee, aaa, bbb, *data[5], 7);
    let (bbb, ddd) = HHH(bbb, ccc, ddd, eee, aaa, *data[1], 15);
    let (aaa, ccc) = HHH(aaa, bbb, ccc, ddd, eee, *data[3], 11);
    let (eee, bbb) = HHH(eee, aaa, bbb, ccc, ddd, *data[7], 8);
    let (ddd, aaa) = HHH(ddd, eee, aaa, bbb, ccc, *data[14], 6);
    let (ccc, eee) = HHH(ccc, ddd, eee, aaa, bbb, *data[6], 6);
    let (bbb, ddd) = HHH(bbb, ccc, ddd, eee, aaa, *data[9], 14);
    let (aaa, ccc) = HHH(aaa, bbb, ccc, ddd, eee, *data[11], 12);
    let (eee, bbb) = HHH(eee, aaa, bbb, ccc, ddd, *data[8], 13);
    let (ddd, aaa) = HHH(ddd, eee, aaa, bbb, ccc, *data[12], 5);
    let (ccc, eee) = HHH(ccc, ddd, eee, aaa, bbb, *data[2], 14);
    let (bbb, ddd) = HHH(bbb, ccc, ddd, eee, aaa, *data[10], 13);
    let (aaa, ccc) = HHH(aaa, bbb, ccc, ddd, eee, *data[0], 13);
    let (eee, bbb) = HHH(eee, aaa, bbb, ccc, ddd, *data[4], 7);
    let (ddd, aaa) = HHH(ddd, eee, aaa, bbb, ccc, *data[13], 5);

    // parallel round 4
    let (ccc, eee) = GGG(ccc, ddd, eee, aaa, bbb, *data[8], 15);
    let (bbb, ddd) = GGG(bbb, ccc, ddd, eee, aaa, *data[6], 5);
    let (aaa, ccc) = GGG(aaa, bbb, ccc, ddd, eee, *data[4], 8);
    let (eee, bbb) = GGG(eee, aaa, bbb, ccc, ddd, *data[1], 11);
    let (ddd, aaa) = GGG(ddd, eee, aaa, bbb, ccc, *data[3], 14);
    let (ccc, eee) = GGG(ccc, ddd, eee, aaa, bbb, *data[11], 14);
    let (bbb, ddd) = GGG(bbb, ccc, ddd, eee, aaa, *data[15], 6);
    let (aaa, ccc) = GGG(aaa, bbb, ccc, ddd, eee, *data[0], 14);
    let (eee, bbb) = GGG(eee, aaa, bbb, ccc, ddd, *data[5], 6);
    let (ddd, aaa) = GGG(ddd, eee, aaa, bbb, ccc, *data[12], 9);
    let (ccc, eee) = GGG(ccc, ddd, eee, aaa, bbb, *data[2], 12);
    let (bbb, ddd) = GGG(bbb, ccc, ddd, eee, aaa, *data[13], 9);
    let (aaa, ccc) = GGG(aaa, bbb, ccc, ddd, eee, *data[9], 12);
    let (eee, bbb) = GGG(eee, aaa, bbb, ccc, ddd, *data[7], 5);
    let (ddd, aaa) = GGG(ddd, eee, aaa, bbb, ccc, *data[10], 15);
    let (ccc, eee) = GGG(ccc, ddd, eee, aaa, bbb, *data[14], 8);

    // parallel round 5
    let (bbb, ddd) = FFF(bbb, ccc, ddd, eee, aaa, *data[12], 8);
    let (aaa, ccc) = FFF(aaa, bbb, ccc, ddd, eee, *data[15], 5);
    let (eee, bbb) = FFF(eee, aaa, bbb, ccc, ddd, *data[10], 12);
    let (ddd, aaa) = FFF(ddd, eee, aaa, bbb, ccc, *data[4], 9);
    let (ccc, eee) = FFF(ccc, ddd, eee, aaa, bbb, *data[1], 12);
    let (bbb, ddd) = FFF(bbb, ccc, ddd, eee, aaa, *data[5], 5);
    let (aaa, ccc) = FFF(aaa, bbb, ccc, ddd, eee, *data[8], 14);
    let (eee, bbb) = FFF(eee, aaa, bbb, ccc, ddd, *data[7], 6);
    let (ddd, aaa) = FFF(ddd, eee, aaa, bbb, ccc, *data[6], 8);
    let (ccc, eee) = FFF(ccc, ddd, eee, aaa, bbb, *data[2], 13);
    let (bbb, ddd) = FFF(bbb, ccc, ddd, eee, aaa, *data[13], 6);
    let (aaa, ccc) = FFF(aaa, bbb, ccc, ddd, eee, *data[14], 5);
    let (eee, bbb) = FFF(eee, aaa, bbb, ccc, ddd, *data[0], 15);
    let (ddd, aaa) = FFF(ddd, eee, aaa, bbb, ccc, *data[3], 13);
    let (ccc, eee) = FFF(ccc, ddd, eee, aaa, bbb, *data[9], 11);
    let (bbb, ddd) = FFF(bbb, ccc, ddd, eee, aaa, *data[11], 11);

    // combine results
    array![
        WrappingAdd::wrapping_add(WrappingAdd::wrapping_add(*s[1], cc), ddd),
        WrappingAdd::wrapping_add(WrappingAdd::wrapping_add(*s[2], dd), eee),
        WrappingAdd::wrapping_add(WrappingAdd::wrapping_add(*s[3], ee), aaa),
        WrappingAdd::wrapping_add(WrappingAdd::wrapping_add(*s[4], aa), bbb),
        WrappingAdd::wrapping_add(WrappingAdd::wrapping_add(*s[0], bb), ccc)
    ]
        .span()
}

/// Returns prepared for compression input and n_chunks
pub(crate) fn pad_input(mut input: Array<u8>) -> (Span<u32>, u32) {
    let n_bytes = input.len();

    /// Optimization for common use case where n_bytes == 32,
    /// e.g. hash160 https://en.bitcoin.it/wiki/Protocol_documentation#Hashes
    ///
    /// OPT: Input is always mapped to X[0..=7] words in single message block, then:
    ///      1. Skip X[8..=13] conversion from Array<u8> to Array<u32> for padding and zeroes.
    ///      2. Assign known values:
    ///          X[14] = lswlen << 3 = 0x0100
    ///          X[15] = (lswlen >> 29) | (mswlen << 3) = 0x00
    if n_bytes == 32 {
        return (
            u8_array_to_u32_array(input)
                .concat(@array![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0100, 0x00])
                .span(),
            1
        );
    }

    // means total chunks
    let n_chunks = n_chunks(n_bytes);

    // padding
    input.append(0x80);

    // n_zeroes = n_chunks - 2 last words - padding_byte - input.len()
    let n_zeroes = n_chunks * 64 - 9 - n_bytes;

    // Append zeroes
    let mut i = 0;
    while i != n_zeroes {
        input.append(0);
        i += 1;
    };

    // Calculate data for indexes X[14*n_chunks], X[15*n_chunks]
    let max_u32: NonZero<u32> = Bounded::<u32>::MAX.try_into().expect('Not a zero');
    let (mswlen, lswlen) = DivRem::div_rem(n_bytes, max_u32);
    let (_, lswlen_sll_3) = DivRem::div_rem(lswlen * 8, max_u32);
    let (_, mswlen_sll_3) = DivRem::div_rem(mswlen * 8, max_u32);
    let (lswlen_srl_29, _) = DivRem::div_rem(n_bytes, POW_2_29.try_into().expect('Not a zero'));

    // Return padded input with concated data for (X[14*n_chunks], X[15*n_chunks])
    (
        u8_array_to_u32_array(input)
            .concat(@array![lswlen_sll_3, mswlen_sll_3 + lswlen_srl_29])
            .span(),
        n_chunks
    )
}

/// Reverse bytes within each u32word
fn u32_array_to_u8_array_le(mut data: Span<u32>) -> Array<u8> {
    let mut result = array![];
    while let Option::Some(val) = data.pop_front() {
        result.append_u32_le(*val);
    };
    result
}

fn n_chunks(n_bytes: u32) -> u32 {
    if n_bytes <= 55 {
        // Input fully maps into one chunk
        return 1;
    } else if n_bytes <= 64 {
        return 2;
    } else {
        let (chunks, rem) = DivRem::div_rem(n_bytes, 64_u32.try_into().expect('Not a zero'));
        if rem <= 55 {
            return chunks + 1;
        } else {
            return chunks + 2;
        }
    }
}

fn u8_array_to_u32_array(data: Array<u8>) -> Array<u32> {
    let mut result = array![];
    let shift = 4;
    let end = data.len();
    let mut position = 0;
    while end - position >= shift {
        result.append(data.word_u32_le(position).unwrap());
        position += shift;
    };
    result
}

// ROL(x, n) cyclically rotates x over n bits to the left
fn ROL(x: u32, n: u32) -> u32 {
    U32BitRotate::rotate_left(x, n)
}

// the ten basic operations FF() through JJJ().
fn ROLASE(a: u32, s: u32, e: u32) -> u32 {
    WrappingAdd::wrapping_add(ROL(a, s), e)
}

fn F(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn G(x: u32, y: u32, z: u32) -> u32 {
    let x_and_y = BitAnd::bitand(x, y);
    let not_x = Bounded::MAX - x;
    let not_x_and_z = BitAnd::bitand(not_x, z);
    BitOr::bitor(x_and_y, not_x_and_z)
}

fn H(x: u32, y: u32, z: u32) -> u32 {
    let not_y = Bounded::MAX - y;
    let x_or_not_y = BitOr::bitor(x, not_y);
    x_or_not_y ^ z
}

fn I(x: u32, y: u32, z: u32) -> u32 {
    let x_and_z = BitAnd::bitand(x, z);
    let not_z = Bounded::MAX - z;
    let y_and_not_z = BitAnd::bitand(y, not_z);
    BitOr::bitor(x_and_z, y_and_not_z)
}

fn J(x: u32, y: u32, z: u32) -> u32 {
    let not_z = Bounded::MAX - z;
    let y_or_not_z = BitOr::bitor(y, not_z);
    x ^ y_or_not_z
}

fn FF(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
    let f_bcd = F(b, c, d);
    let a = WrappingAdd::wrapping_add(a, f_bcd);
    let a = WrappingAdd::wrapping_add(a, x);
    let res1 = ROLASE(a, s, e);
    let res2 = ROL(c, 10);
    (res1, res2)
}

fn GG(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
    let g_bcd = G(b, c, d);
    let a = WrappingAdd::wrapping_add(a, g_bcd);
    let a = WrappingAdd::wrapping_add(a, x);
    let a = WrappingAdd::wrapping_add(a, 0x5a827999);
    let res1 = ROLASE(a, s, e);
    let res2 = ROL(c, 10);
    (res1, res2)
}

fn HH(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
    let h_bcd = H(b, c, d);
    let a = WrappingAdd::wrapping_add(a, h_bcd);
    let a = WrappingAdd::wrapping_add(a, x);
    let a = WrappingAdd::wrapping_add(a, 0x6ed9eba1);
    let res1 = ROLASE(a, s, e);
    let res2 = ROL(c, 10);
    (res1, res2)
}

fn II(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
    let i_bcd = I(b, c, d);
    let a = WrappingAdd::wrapping_add(a, i_bcd);
    let a = WrappingAdd::wrapping_add(a, x);
    let a = WrappingAdd::wrapping_add(a, 0x8f1bbcdc);
    let res1 = ROLASE(a, s, e);
    let res2 = ROL(c, 10);
    (res1, res2)
}

fn JJ(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
    let j_bcd = J(b, c, d);
    let a = WrappingAdd::wrapping_add(a, j_bcd);
    let a = WrappingAdd::wrapping_add(a, x);
    let a = WrappingAdd::wrapping_add(a, 0xa953fd4e);
    let res1 = ROLASE(a, s, e);
    let res2 = ROL(c, 10);
    (res1, res2)
}

fn FFF(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
    FF(a, b, c, d, e, x, s)
}

fn GGG(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
    let g_bcd = G(b, c, d);
    let a = WrappingAdd::wrapping_add(a, g_bcd);
    let a = WrappingAdd::wrapping_add(a, x);
    let a = WrappingAdd::wrapping_add(a, 0x7a6d76e9);
    let res1 = ROLASE(a, s, e);
    let res2 = ROL(c, 10);
    (res1, res2)
}

fn HHH(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
    let h_bcd = H(b, c, d);
    let a = WrappingAdd::wrapping_add(a, h_bcd);
    let a = WrappingAdd::wrapping_add(a, x);
    let a = WrappingAdd::wrapping_add(a, 0x6d703ef3);
    let res1 = ROLASE(a, s, e);
    let res2 = ROL(c, 10);
    (res1, res2)
}

fn III(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
    let i_bcd = I(b, c, d);
    let a = WrappingAdd::wrapping_add(a, i_bcd);
    let a = WrappingAdd::wrapping_add(a, x);
    let a = WrappingAdd::wrapping_add(a, 0x5c4dd124);
    let res1 = ROLASE(a, s, e);
    let res2 = ROL(c, 10);
    (res1, res2)
}

fn JJJ(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
    let j_bcd = J(b, c, d);
    let a = WrappingAdd::wrapping_add(a, j_bcd);
    let a = WrappingAdd::wrapping_add(a, x);
    let a = WrappingAdd::wrapping_add(a, 0x50a28be6);
    let res1 = ROLASE(a, s, e);
    let res2 = ROL(c, 10);
    (res1, res2)
}
