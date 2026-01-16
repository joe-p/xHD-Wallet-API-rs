#[derive(Debug, PartialEq, Eq)]
pub enum DerivationType {
    Soft(u32),
    Hard(u32),
}

/// Derivation index is a 32 bits number representing
/// a type of derivation and a 31 bits number.
///
/// The highest bit set represent a hard derivation,
/// whereas the bit clear represent soft derivation.
pub type DerivationIndex = u32;

impl DerivationType {
    pub fn from_index(index: DerivationIndex) -> Self {
        if index >= 0x80000000 {
            DerivationType::Hard(index)
        } else {
            DerivationType::Soft(index)
        }
    }
}

/// Ed25519-bip32 Scheme Derivation version
///
/// V2 is the standard BIP32-ed25519 derivation scheme.
/// Peikert is Chris Peikert's amendment that preserves more bits for improved security.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationScheme {
    /// Standard BIP32-ed25519 derivation (truncates zL to 28 bytes / 224 bits)
    V2,
    /// Chris Peikert's amendment to BIP32-ed25519 (truncates zL to 247 bits)
    ///
    /// This scheme preserves more bits from zL during derivation, providing
    /// improved security guarantees. It uses g=9, which allows up to 2^3 = 8
    /// derivation levels safely (BIP44 needs 5).
    ///
    /// The relationship is: g >= d + 6, where D = 2^d is the maximum derivation depth.
    Peikert,
}

impl DerivationScheme {
    /// Returns the 'g' parameter for the derivation scheme.
    ///
    /// 'g' controls how many bits are zeroed from the top of the 256-bit value during truncation.
    /// - V2: g=32 (keeps 224 bits)
    /// - Peikert: g=9 (keeps 247 bits)
    pub fn g(self) -> u8 {
        match self {
            DerivationScheme::V2 => 32,
            DerivationScheme::Peikert => 9,
        }
    }
}

impl Default for DerivationScheme {
    fn default() -> Self {
        DerivationScheme::V2
    }
}
