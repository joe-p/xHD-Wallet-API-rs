use crate::DerivationScheme;

/// Peikert's amendment to BIP32-ed25519: truncate to (256 - g) bits, then add with x after multiplying by 8
///
/// The `g` parameter controls how many bits to zero from the top of the 256-bit value.
/// - g=32: Standard BIP32-ed25519 (256-32=224 bits = 28 bytes kept)
/// - g=9: Peikert's recommended value (256-9=247 bits kept, allows 2^3=8 derivation levels safely)
///
/// The relationship is: g >= d + 6, where D = 2^d is the maximum derivation depth.
/// With g=9 and d=3, we get D=8 max derivation levels (BIP44 needs 5).
pub fn add_mul8(x: &[u8; 32], y: &[u8; 32], scheme: DerivationScheme) -> [u8; 32] {
    // Truncate y to (256 - g) bits
    let truncated = trunc_256_minus_g_bits(y, scheme);

    let mut carry: u16 = 0;
    let mut out = [0u8; 32];

    for i in 0..32 {
        let r = x[i] as u16 + ((truncated[i] as u16) << 3) + carry;
        out[i] = (r & 0xff) as u8;
        carry = r >> 8;
    }
    out
}

/// Truncates a 256-bit little-endian value to (256 - g) bits by zeroing the top g bits.
///
/// For example:
/// - Peikert g=9: keeps 247 bits (30 full bytes + 7 bits of byte 30, zeros top bit of byte 30 and all of byte 31)
/// - v2 g=32: keeps 224 bits (28 full bytes, zeros bytes 28-31)
fn trunc_256_minus_g_bits(y: &[u8; 32], scheme: DerivationScheme) -> [u8; 32] {
    let mut out = *y;

    let g = scheme.g();
    let remainder = g % 8;
    let mask_byte = if remainder == 0 { 0 } else { 0xff >> remainder };
    let zero_start = ((256 - g as u16) / 8) as usize;

    out[zero_start] &= mask_byte;
    out[(zero_start + 1)..].fill(0);

    out
}

pub fn add_256bits_v2(x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    let mut carry: u16 = 0;
    let mut out = [0u8; 32];
    for i in 0..32 {
        let r = (x[i] as u16) + (y[i] as u16) + carry;
        out[i] = r as u8;
        carry = r >> 8;
    }
    out
}

pub fn le32(i: u32) -> [u8; 4] {
    [i as u8, (i >> 8) as u8, (i >> 16) as u8, (i >> 24) as u8]
}
