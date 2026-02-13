use crate::{DerivationIndex, DerivationScheme, Signature, XPrv};

/// Errors that can occur during key derivation.
#[derive(Debug)]
pub enum DerivationError {
    /// The index is already hardened and cannot be hardened again.
    AlreadyHardened,
}

/// Context for key derivation, determining the coin type and purpose.
pub enum KeyContext {
    /// Address context for Algorand addresses (coin type 283).
    Address,
    /// Identity context for identity keys (coin type 0).
    Identity,
}

impl KeyContext {
    /// Returns the BIP44 coin type for this context.
    ///
    /// - Address: 283 (Algorand)
    /// - Identity: 0
    pub fn coin_type(&self) -> DerivationIndex {
        match self {
            KeyContext::Address => 283,
            KeyContext::Identity => 0,
        }
    }
}

const HARDENED_OFFSET: u32 = 0x80_00_00_00;

/// Hardens a derivation index by adding the hardened offset.
///
/// # Arguments
///
/// * `index` - The derivation index to harden
///
/// # Returns
///
/// * `Ok(DerivationIndex)` - The hardened index
/// * `Err(DerivationError::AlreadyHardened)` - If the index is already hardened
pub fn harden(index: DerivationIndex) -> Result<DerivationIndex, DerivationError> {
    index
        .checked_add(HARDENED_OFFSET)
        .ok_or(DerivationError::AlreadyHardened)
}

/// Derives a child key along a path of derivation indices.
///
/// # Arguments
///
/// * `root_xprv` - The root extended private key
/// * `path` - The derivation path as a slice of indices
/// * `scheme` - The derivation scheme to use
///
/// # Returns
///
/// The derived extended private key at the end of the path
fn derive_path(root_xprv: &XPrv, path: &[DerivationIndex], scheme: DerivationScheme) -> XPrv {
    let mut current_xprv = root_xprv.clone();
    for &index in path {
        current_xprv = current_xprv.derive(scheme, index);
    }
    current_xprv
}

/// Generates a key using the BIP44 derivation path.
///
/// Derives a key at path: m'/44'/<coin_type>'/<account>'/0/<key_index>
///
/// # Arguments
///
/// * `root_key` - The root extended private key
/// * `context` - The key context (Address or Identity)
/// * `account` - The account index (hardened)
/// * `key_index` - The key index within the account
/// * `scheme` - The derivation scheme to use
///
/// # Returns
///
/// * `Ok(XPrv)` - The derived extended private key
/// * `Err(DerivationError)` - If derivation fails
pub fn key_gen(
    root_key: &XPrv,
    context: KeyContext,
    account: DerivationIndex,
    key_index: DerivationIndex,
    scheme: DerivationScheme,
) -> Result<XPrv, DerivationError> {
    let bip44_path = [
        harden(44)?,
        harden(context.coin_type())?,
        harden(account)?,
        0,
        key_index,
    ];

    Ok(derive_path(root_key, &bip44_path, scheme))
}

/// Signs data using a key derived from the given BIP44 path.
///
/// # Arguments
///
/// * `root_key` - The root extended private key
/// * `bip44_path` - The BIP44 derivation path
/// * `data` - The data to sign
/// * `scheme` - The derivation scheme to use
///
/// # Returns
///
/// The signature as a byte vector
pub fn raw_sign(
    root_key: &XPrv,
    bip44_path: &[DerivationIndex],
    data: &[u8],
    scheme: DerivationScheme,
) -> Vec<u8> {
    let derived_xprv = derive_path(root_key, bip44_path, scheme);
    let signature: Signature<Vec<u8>> = derived_xprv.sign(data);
    signature.to_bytes().to_vec()
}

/// Signs a transaction using a key derived via BIP44 path.
///
/// Derives a key at path: m'/44'/<coin_type>'/<account>'/0/<key_index>
/// and signs the provided transaction data.
///
/// # Arguments
///
/// * `root_key` - The root extended private key
/// * `context` - The key context (Address or Identity)
/// * `account` - The account index (hardened)
/// * `key_index` - The key index within the account
/// * `prefix_encoded_tx` - The transaction data to sign
/// * `scheme` - The derivation scheme to use
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The signature as a byte vector
/// * `Err(DerivationError)` - If derivation fails
pub fn sign(
    root_key: &XPrv,
    context: KeyContext,
    account: DerivationIndex,
    key_index: DerivationIndex,
    prefix_encoded_tx: &[u8],
    scheme: DerivationScheme,
) -> Result<Vec<u8>, DerivationError> {
    let bip44_path = [
        harden(44)?,
        harden(context.coin_type())?,
        harden(account)?,
        0,
        key_index,
    ];

    Ok(raw_sign(root_key, &bip44_path, prefix_encoded_tx, scheme))
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::*;

    fn base64_decode(s: &str) -> Vec<u8> {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.decode(s).unwrap()
    }

    const SEED_HEX: &str = "3aff2db416b895ec3cf9a4f8d1e970bc9819920e7bf44a5e350477af0ef557b1511b0986debf78dd38c7c520cd44ff7c7231618f958e21ef0250733a8c1915ea";
    const ROOT_KEY_HEX: &str = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";

    /// Helper to convert hex string to bytes
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key_gen_test(
        key_context: KeyContext,
        account: DerivationIndex,
        index: DerivationIndex,
        expected_public_key_hex: &str,
    ) -> Result<(), DerivationError> {
        let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
        let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

        let public_key = key_gen(
            &root_xprv,
            key_context,
            account,
            index,
            DerivationScheme::Peikert,
        )?
        .public();

        let expected_public_key = hex_to_bytes(expected_public_key_hex);

        assert_eq!(
            public_key.public_key_slice(),
            expected_public_key.as_slice(),
            "Derived Algorand address public key should match expected value"
        );
        Ok(())
    }

    #[test]
    fn test_from_seed() {
        let seed_bytes = hex_to_bytes(SEED_HEX);
        let xprv = XPrv::from_seed(&seed_bytes.as_slice().try_into().unwrap());
        let xprv_bytes: [u8; 96] = xprv.into();

        let expected_root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);

        assert_eq!(
            xprv_bytes,
            expected_root_key_bytes.as_slice(),
            "Derived root key should match expected value"
        );
    }

    // Test: Derive m'/44'/283'/0'/0/0 Algorand Address Key
    // This matches the TypeScript test:
    // it("(OK) Derive m'/44'/283'/0'/0/0 Algorand Address Key", async () => {
    //     const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Address, 0, 0)
    //     expect(key).toEqual(new Uint8Array(Buffer.from("7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9", "hex")))
    // })
    // it("\(OK) Derive m'/44'/283'/0'/0/1 Algorand Address Key", async () => {
    //        const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Address, 0, 1)
    //        expect(key).toEqual(new Uint8Array(Buffer.from("5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519", "hex")))
    //    })
    //
    //    it("\(OK) Derive m'/44'/283'/0'/0/2 Algorand Address Key", async () => {
    //        const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Address, 0, 2)
    //        expect(key).toEqual(new Uint8Array(Buffer.from("00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3", "hex")))
    //    })
    #[test]
    fn algorand_soft_derivation() -> Result<(), DerivationError> {
        key_gen_test(
            KeyContext::Address,
            0,
            0,
            "7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9",
        )?;

        key_gen_test(
            KeyContext::Address,
            0,
            1,
            "5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519",
        )?;

        key_gen_test(
            KeyContext::Address,
            0,
            2,
            "00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3",
        )?;
        Ok(())
    }
    //
    // it("\(OK) Derive m'/44'/283'/1'/0/0 Algorand Address Key", async () => {
    //         const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Address, 1, 0)
    //         expect(key).toEqual(new Uint8Array(Buffer.from("358d8c4382992849a764438e02b1c45c2ca4e86bbcfe10fd5b963f3610012bc9", "hex")))
    //     })
    //
    //     it("\(OK) Derive m'/44'/283'/2'/0/1 Algorand Address Key", async () => {
    //         const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Address, 2, 1)
    //         expect(key).toEqual(new Uint8Array(Buffer.from("1f0f75fbbca12b22523973191061b2f96522740e139a3420c730717ac5b0dfc0", "hex")))
    //     })
    //
    //     it("\(OK) Derive m'/44'/283'/3'/0/0 Algorand Address Key", async () => {
    //         const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Address, 3, 0)
    //         expect(key).toEqual(new Uint8Array(Buffer.from("f035316f915b342ea5fe78dccb59d907b93805732219d436a1bd8488ff4e5b1b", "hex")))
    //     })
    #[test]
    fn algorand_hard_derivation() -> Result<(), DerivationError> {
        key_gen_test(
            KeyContext::Address,
            1,
            0,
            "358d8c4382992849a764438e02b1c45c2ca4e86bbcfe10fd5b963f3610012bc9",
        )?;

        key_gen_test(
            KeyContext::Address,
            2,
            1,
            "1f0f75fbbca12b22523973191061b2f96522740e139a3420c730717ac5b0dfc0",
        )?;

        key_gen_test(
            KeyContext::Address,
            3,
            0,
            "f035316f915b342ea5fe78dccb59d907b93805732219d436a1bd8488ff4e5b1b",
        )?;
        Ok(())
    }

    // it("\(OK) Derive m'/44'/0'/0'/0/0 Identity Key", async () => {
    //            const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Identity, 0, 0)
    //            expect(key).toEqual(new Uint8Array(Buffer.from("ff8b1863ef5e40d0a48c245f26a6dbdf5da94dc75a1851f51d8a04e547bd5f5a", "hex")))
    //        })
    //
    //        it("\(OK) Derive m'/44'/0'/0'/0/1 Identity Key", async () => {
    //            const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Identity, 0, 1)
    //            expect(key).toEqual(new Uint8Array(Buffer.from("2b46c2af0890493e486049d456509a0199e565b41a5fb622f0ea4b9337bd2b97", "hex")))
    //        })
    //
    //        it("\(OK) Derive m'/44'/0'/0'/0/2 Identity Key", async () => {
    //            const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Identity, 0, 2)
    //            expect(key).toEqual(new Uint8Array(Buffer.from("2713f135f19ef3dcfca73cb536b1e077b1165cd0b7bedbef709447319ff0016d", "hex")))
    //        })
    #[test]
    fn identity_soft_derivation() -> Result<(), DerivationError> {
        key_gen_test(
            KeyContext::Identity,
            0,
            0,
            "ff8b1863ef5e40d0a48c245f26a6dbdf5da94dc75a1851f51d8a04e547bd5f5a",
        )?;

        key_gen_test(
            KeyContext::Identity,
            0,
            1,
            "2b46c2af0890493e486049d456509a0199e565b41a5fb622f0ea4b9337bd2b97",
        )?;

        key_gen_test(
            KeyContext::Identity,
            0,
            2,
            "2713f135f19ef3dcfca73cb536b1e077b1165cd0b7bedbef709447319ff0016d",
        )?;
        Ok(())
    }

    // it("\(OK) Derive m'/44'/0'/1'/0/0 Identity Key", async () => {
    //                const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Identity, 1, 0)
    //                expect(key).toEqual(new Uint8Array(Buffer.from("232847ae1bb95babcaa50c8033fab98f59e4b4ad1d89ac523a90c830e4ceee4a", "hex")))
    //            })
    //
    //            it("\(OK) Derive m'/44'/0'/2'/0/1 Identity Key", async () => {
    //                const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Identity, 2, 1)
    //                expect(key).toEqual(new Uint8Array(Buffer.from("8f68b6572860d84e8a41e38db1c8c692ded5eb291846f2e5bbfde774a9c6d16e", "hex")))
    //            })
    #[test]
    fn identity_hard_derivation() -> Result<(), DerivationError> {
        key_gen_test(
            KeyContext::Identity,
            1,
            0,
            "232847ae1bb95babcaa50c8033fab98f59e4b4ad1d89ac523a90c830e4ceee4a",
        )?;

        key_gen_test(
            KeyContext::Identity,
            2,
            1,
            "8f68b6572860d84e8a41e38db1c8c692ded5eb291846f2e5bbfde774a9c6d16e",
        )?;
        Ok(())
    }

    // Test: Root Key format
    // it("(OK) Root Key", async () => {
    //     expect(rootKey.length).toBe(96)
    //     expect(Buffer.from(rootKey)).toEqual(Buffer.from("a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946", "hex"))
    // })
    #[test]
    fn root_key_format() {
        let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
        assert_eq!(root_key_bytes.len(), 96, "Root key should be 96 bytes");
    }

    // Test: BIP32-Ed25519 derive key m'/44'/283'/0'/0/0 using Khovratovich (V2) scheme
    // it("(OK) BIP32-Ed25519 derive key m'/44'/283'/0'/0/0", async () => {
    //     const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Address, 0, 0, BIP32DerivationType.Khovratovich)
    //     ...
    //     expect(derivedPub).toEqual(key)
    // })
    #[test]
    fn bip32_ed25519_khovratovich_derive_address_0_0() -> Result<(), DerivationError> {
        let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
        let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

        let bip44_path = [harden(44)?, harden(283)?, harden(0)?, 0, 0];

        let mut current_xprv = root_xprv.clone();
        for &index in &bip44_path {
            current_xprv = current_xprv.derive(DerivationScheme::V2, index);
        }

        let public_key = current_xprv.public().public_key();
        let expected_key_gen =
            key_gen(&root_xprv, KeyContext::Address, 0, 0, DerivationScheme::V2)?
                .public()
                .public_key();

        assert_eq!(
            public_key, expected_key_gen,
            "Khovratovich derivation should match key_gen"
        );
        Ok(())
    }

    // Test: BIP32-Ed25519 derive key m'/44'/283'/0'/0/1 using Khovratovich (V2) scheme
    #[test]
    fn bip32_ed25519_khovratovich_derive_address_0_1() -> Result<(), DerivationError> {
        let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
        let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

        let bip44_path = [harden(44)?, harden(283)?, harden(0)?, 0, 1];

        let mut current_xprv = root_xprv.clone();
        for &index in &bip44_path {
            current_xprv = current_xprv.derive(DerivationScheme::V2, index);
        }

        let public_key = current_xprv.public().public_key();
        let expected_key_gen =
            key_gen(&root_xprv, KeyContext::Address, 0, 1, DerivationScheme::V2)?
                .public()
                .public_key();

        assert_eq!(
            public_key, expected_key_gen,
            "Khovratovich derivation should match key_gen"
        );
        Ok(())
    }

    // Test: BIP32-Ed25519 derive PUBLIC key m'/44'/283'/1'/0/1 using Khovratovich (V2) scheme
    // it("(OK) BIP32-Ed25519 derive PUBLIC key m'/44'/283'/1'/0/1", async () => {
    //     ...
    // })
    #[test]
    fn bip32_ed25519_khovratovich_derive_public_address_1_1() -> Result<(), DerivationError> {
        let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
        let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

        let bip44_path_private = [harden(44)?, harden(283)?, harden(1)?, 0, 1];

        let mut current_xprv = root_xprv.clone();
        for &index in &bip44_path_private[..3] {
            current_xprv = current_xprv.derive(DerivationScheme::V2, index);
        }

        let wallet_level_xpub = current_xprv.public();

        let derived_pub = wallet_level_xpub
            .derive(DerivationScheme::V2, 0)
            .unwrap()
            .derive(DerivationScheme::V2, 1)
            .unwrap()
            .public_key();

        let expected_key_gen =
            key_gen(&root_xprv, KeyContext::Address, 1, 1, DerivationScheme::V2)?
                .public()
                .public_key();

        assert_eq!(
            derived_pub, expected_key_gen,
            "Public derivation should match private derivation"
        );
        Ok(())
    }

    // Test: BIP32-Ed25519 derive PUBLIC key m'/44'/0'/1'/0/2 using Khovratovich (V2) scheme
    #[test]
    fn bip32_ed25519_khovratovich_derive_public_identity_1_2() -> Result<(), DerivationError> {
        let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
        let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

        let bip44_path_private = [harden(44)?, harden(0)?, harden(1)?, 0, 2];

        let mut current_xprv = root_xprv.clone();
        for &index in &bip44_path_private[..3] {
            current_xprv = current_xprv.derive(DerivationScheme::V2, index);
        }

        let wallet_level_xpub = current_xprv.public();

        let derived_pub = wallet_level_xpub
            .derive(DerivationScheme::V2, 0)
            .unwrap()
            .derive(DerivationScheme::V2, 2)
            .unwrap()
            .public_key();

        let expected_key_gen =
            key_gen(&root_xprv, KeyContext::Identity, 1, 2, DerivationScheme::V2)?
                .public()
                .public_key();

        assert_eq!(
            derived_pub, expected_key_gen,
            "Public derivation should match private derivation"
        );
        Ok(())
    }

    // Test: Sign and verify a message
    #[test]
    fn sign_and_verify_message() -> Result<(), DerivationError> {
        let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
        let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

        let message = b"Hello, World!";

        let xprv = key_gen(
            &root_xprv,
            KeyContext::Address,
            0,
            0,
            DerivationScheme::Peikert,
        )?;
        let xpub = xprv.public();

        let signature: Signature<Vec<u8>> = xprv.sign(message);

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(
            xpub.verify(message, &signature),
            "Signature should be valid"
        );
        Ok(())
    }

    // Test: Sign transaction
    // it("(OK) Sign Transaction", async () => {
    //     const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Address, 0, 0, BIP32DerivationType.Khovratovich)
    //     const prefixEncodedTx = new Uint8Array(Buffer.from('VFiJo2FtdM0D6KNmZWXNA+iiZnbOAkeSd6NnZW6sdGVzdG5ldC12MS4womhoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds4CR5Zfo3JjdsQgYv6DK3rRBUS+gzemcENeUGSuSmbne9eJCXZbRrV2pvOjc25kxCBi/oMretEFRL6DN6ZwQ15QZK5KZud714kJdltGtXam86R0eXBlo3BheQ==', 'base64'))
    //     const sig = await cryptoService.signAlgoTransaction(rootKey, KeyContext.Address, 0, 0, prefixEncodedTx, BIP32DerivationType.Khovratovich)
    //     expect(nacl.sign.detached.verify(prefixEncodedTx, sig, key)).toBe(true)
    // })
    #[test]
    fn sign_transaction() -> Result<(), DerivationError> {
        let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
        let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

        let xprv = key_gen(&root_xprv, KeyContext::Address, 0, 0, DerivationScheme::V2)?;
        let xpub = xprv.public();

        let prefix_encoded_tx = base64_decode("VFiJo2FtdM0D6KNmZWXNA+iiZnbOAkeSd6NnZW6sdGVzdG5ldC12MS4womhoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds4CR5Zfo3JjdsQgYv6DK3rRBUS+gzemcENeUGSuSmbne9eJCXZbRrV2pvOjc25kxCBi/oMretEFRL6DN6ZwQ15QZK5KZud714kJdltGtXam86R0eXBlo3BheQ==");

        let sig = sign(
            &root_xprv,
            KeyContext::Address,
            0,
            0,
            &prefix_encoded_tx,
            DerivationScheme::V2,
        )?;

        assert_eq!(sig.len(), 64, "Signature should be 64 bytes");
        assert!(
            xpub.verify(
                &prefix_encoded_tx,
                &Signature::<u8>::from_slice(&sig).unwrap()
            ),
            "Signature should be valid for the transaction"
        );
        Ok(())
    }

    // Test: deriveNodePublic - derive N keys with only public information
    // it("(OK) From m'/44'/283'/0'/0 root level derive N keys with only public information", async () => {
    //     ...
    // })
    #[test]
    fn derive_node_public_soft_derivation() -> Result<(), DerivationError> {
        let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
        let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

        let wallet_root_path = [harden(44)?, harden(283)?, harden(0)?, 0];

        let mut wallet_root_xprv = root_xprv.clone();
        for &index in &wallet_root_path {
            wallet_root_xprv = wallet_root_xprv.derive(DerivationScheme::Peikert, index);
        }

        let wallet_root_xpub = wallet_root_xprv.public();

        let num_public_keys_to_derive = 10;
        for i in 0..num_public_keys_to_derive {
            let derived_xpub = wallet_root_xpub
                .derive(DerivationScheme::Peikert, i)
                .unwrap();
            let my_key = key_gen(
                &root_xprv,
                KeyContext::Address,
                0,
                i,
                DerivationScheme::Peikert,
            )?
            .public()
            .public_key();

            assert_eq!(
                derived_xpub.public_key(),
                my_key,
                "Public derivation at index {} should match private derivation",
                i
            );
        }
        Ok(())
    }

    // Test: deriveNodePublic - should NOT derive correct addresses from hardened root
    // it("(FAIL) From m'/44'/283'/0'/0' root level should not be able to derive correct addresses from a hardened derivation", async () => {
    //     ...
    // })
    #[test]
    fn derive_node_public_hard_derivation_mismatch() -> Result<(), DerivationError> {
        let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
        let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

        let wallet_root_path = [harden(44)?, harden(283)?, harden(0)?, harden(0)?];

        let mut wallet_root_xprv = root_xprv.clone();
        for &index in &wallet_root_path {
            wallet_root_xprv = wallet_root_xprv.derive(DerivationScheme::Peikert, index);
        }

        let wallet_root_xpub = wallet_root_xprv.public();

        let num_public_keys_to_derive = 10;
        for i in 0..num_public_keys_to_derive {
            let derived_xpub = wallet_root_xpub
                .derive(DerivationScheme::Peikert, i)
                .unwrap();
            let my_key = key_gen(
                &root_xprv,
                KeyContext::Address,
                0,
                i,
                DerivationScheme::Peikert,
            )?
            .public()
            .public_key();

            assert_ne!(
            derived_xpub.public_key(),
            my_key,
            "Public derivation from hardened root should NOT match private derivation at index {}",
            i
        );
        }
        Ok(())
    }
}
