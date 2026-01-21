use crate::api::{harden, key_gen, sign, KeyContext};
use crate::{DerivationScheme, Signature, XPrv};

use super::*;

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.decode(s).unwrap()
}

const D1: [u8; XPRV_SIZE] = [
    0xf8, 0xa2, 0x92, 0x31, 0xee, 0x38, 0xd6, 0xc5, 0xbf, 0x71, 0x5d, 0x5b, 0xac, 0x21, 0xc7, 0x50,
    0x57, 0x7a, 0xa3, 0x79, 0x8b, 0x22, 0xd7, 0x9d, 0x65, 0xbf, 0x97, 0xd6, 0xfa, 0xde, 0xa1, 0x5a,
    0xdc, 0xd1, 0xee, 0x1a, 0xbd, 0xf7, 0x8b, 0xd4, 0xbe, 0x64, 0x73, 0x1a, 0x12, 0xde, 0xb9, 0x4d,
    0x36, 0x71, 0x78, 0x41, 0x12, 0xeb, 0x6f, 0x36, 0x4b, 0x87, 0x18, 0x51, 0xfd, 0x1c, 0x9a, 0x24,
    0x73, 0x84, 0xdb, 0x9a, 0xd6, 0x00, 0x3b, 0xbd, 0x08, 0xb3, 0xb1, 0xdd, 0xc0, 0xd0, 0x7a, 0x59,
    0x72, 0x93, 0xff, 0x85, 0xe9, 0x61, 0xbf, 0x25, 0x2b, 0x33, 0x12, 0x62, 0xed, 0xdf, 0xad, 0x0d,
];

const D1_H0: [u8; XPRV_SIZE] = [
    0x60, 0xd3, 0x99, 0xda, 0x83, 0xef, 0x80, 0xd8, 0xd4, 0xf8, 0xd2, 0x23, 0x23, 0x9e, 0xfd, 0xc2,
    0xb8, 0xfe, 0xf3, 0x87, 0xe1, 0xb5, 0x21, 0x91, 0x37, 0xff, 0xb4, 0xe8, 0xfb, 0xde, 0xa1, 0x5a,
    0xdc, 0x93, 0x66, 0xb7, 0xd0, 0x03, 0xaf, 0x37, 0xc1, 0x13, 0x96, 0xde, 0x9a, 0x83, 0x73, 0x4e,
    0x30, 0xe0, 0x5e, 0x85, 0x1e, 0xfa, 0x32, 0x74, 0x5c, 0x9c, 0xd7, 0xb4, 0x27, 0x12, 0xc8, 0x90,
    0x60, 0x87, 0x63, 0x77, 0x0e, 0xdd, 0xf7, 0x72, 0x48, 0xab, 0x65, 0x29, 0x84, 0xb2, 0x1b, 0x84,
    0x97, 0x60, 0xd1, 0xda, 0x74, 0xa6, 0xf5, 0xbd, 0x63, 0x3c, 0xe4, 0x1a, 0xdc, 0xee, 0xf0, 0x7a,
];

const MSG: &[u8] = b"Hello World";

const D1_H0_SIGNATURE: [u8; 64] = [
    0x90, 0x19, 0x4d, 0x57, 0xcd, 0xe4, 0xfd, 0xad, 0xd0, 0x1e, 0xb7, 0xcf, 0x16, 0x17, 0x80, 0xc2,
    0x77, 0xe1, 0x29, 0xfc, 0x71, 0x35, 0xb9, 0x77, 0x79, 0xa3, 0x26, 0x88, 0x37, 0xe4, 0xcd, 0x2e,
    0x94, 0x44, 0xb9, 0xbb, 0x91, 0xc0, 0xe8, 0x4d, 0x23, 0xbb, 0xa8, 0x70, 0xdf, 0x3c, 0x4b, 0xda,
    0x91, 0xa1, 0x10, 0xef, 0x73, 0x56, 0x38, 0xfa, 0x7a, 0x34, 0xea, 0x20, 0x46, 0xd4, 0xbe, 0x04,
];

fn compare_xprv(xprv: &[u8], expected_xprv: &[u8]) {
    assert_eq!(
        xprv[64..].to_vec(),
        expected_xprv[64..].to_vec(),
        "chain code"
    );
    assert_eq!(
        xprv[..64].to_vec(),
        expected_xprv[..64].to_vec(),
        "extended key"
    );
}

fn derive_xprv_eq(parent_xprv: &XPrv, idx: DerivationIndex, expected_xprv: [u8; 96]) {
    let child_xprv = parent_xprv.derive(DerivationScheme::V2, idx);
    compare_xprv(child_xprv.as_ref(), &expected_xprv);
}

fn do_sign(xprv: &XPrv, expected_signature: &[u8]) {
    let signature: Signature<Vec<u8>> = xprv.sign(MSG);
    assert_eq!(signature.as_ref(), expected_signature);
}

#[test]
fn xprv_sign() {
    let prv = XPrv::from_bytes_verified(D1_H0).unwrap();
    assert!(prv.is_3rd_highest_bit_clear());
    do_sign(&prv, &D1_H0_SIGNATURE);
}

#[test]
fn verify_signature() {
    let prv = XPrv::from_bytes_verified(D1_H0).unwrap();
    assert!(prv.is_3rd_highest_bit_clear());
    let xpub = prv.public();
    let sig: Signature<u8> = Signature::from_slice(&D1_H0_SIGNATURE).unwrap();
    assert_eq!(xpub.verify(MSG, &sig), true)
}

#[test]
fn xprv_derive() {
    let prv = XPrv::from_bytes_verified(D1).unwrap();
    assert!(prv.is_3rd_highest_bit_clear());
    derive_xprv_eq(&prv, 0x80000000, D1_H0);
}

#[test]
fn marshall_xprv() {
    let bytes = [1u8; 96];
    let xprv = XPrv::normalize_bytes_force3rd(bytes);
    let esk = xprv.extended_secret_key();
    let cc = xprv.chain_code();
    let xprv2 = XPrv::from_extended_and_chaincode(&esk, &cc);
    assert_eq!(xprv.public(), xprv2.public());
    assert_eq!(cc, xprv.public().chain_code());
}

#[test]
fn xprv_derive_peikert() {
    // Test that derivation with Peikert scheme works
    let prv = XPrv::from_bytes_verified(D1).unwrap();
    assert!(prv.is_3rd_highest_bit_clear());

    // Derive with Peikert scheme
    let child_peikert = prv.derive(DerivationScheme::Peikert, 0x80000000);

    // Derive with standard V2 scheme
    let child_v2 = prv.derive(DerivationScheme::V2, 0x80000000);

    // Peikert derivation should produce a different result than V2
    // (because it keeps more bits from zL)
    assert_ne!(child_peikert.as_ref(), child_v2.as_ref());

    // Both should be valid keys (can sign and verify)
    let msg = b"test message";
    let sig_peikert: Signature<Vec<u8>> = child_peikert.sign(msg);
    let sig_v2: Signature<Vec<u8>> = child_v2.sign(msg);

    assert!(child_peikert.verify(msg, &sig_peikert));
    assert!(child_v2.verify(msg, &sig_v2));
}

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
) {
    let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
    let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

    let public_key = key_gen(
        root_xprv,
        key_context,
        account,
        index,
        DerivationScheme::Peikert,
    )
    .public();

    let expected_public_key = hex_to_bytes(expected_public_key_hex);

    assert_eq!(
        public_key.public_key_slice(),
        expected_public_key.as_slice(),
        "Derived Algorand address public key should match expected value"
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
fn algorand_soft_derivation() {
    key_gen_test(
        KeyContext::Address,
        0,
        0,
        "7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9",
    );

    key_gen_test(
        KeyContext::Address,
        0,
        1,
        "5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519",
    );

    key_gen_test(
        KeyContext::Address,
        0,
        2,
        "00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3",
    );
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
fn algorand_hard_derivation() {
    key_gen_test(
        KeyContext::Address,
        1,
        0,
        "358d8c4382992849a764438e02b1c45c2ca4e86bbcfe10fd5b963f3610012bc9",
    );

    key_gen_test(
        KeyContext::Address,
        2,
        1,
        "1f0f75fbbca12b22523973191061b2f96522740e139a3420c730717ac5b0dfc0",
    );

    key_gen_test(
        KeyContext::Address,
        3,
        0,
        "f035316f915b342ea5fe78dccb59d907b93805732219d436a1bd8488ff4e5b1b",
    );
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
fn identity_soft_derivation() {
    key_gen_test(
        KeyContext::Identity,
        0,
        0,
        "ff8b1863ef5e40d0a48c245f26a6dbdf5da94dc75a1851f51d8a04e547bd5f5a",
    );

    key_gen_test(
        KeyContext::Identity,
        0,
        1,
        "2b46c2af0890493e486049d456509a0199e565b41a5fb622f0ea4b9337bd2b97",
    );

    key_gen_test(
        KeyContext::Identity,
        0,
        2,
        "2713f135f19ef3dcfca73cb536b1e077b1165cd0b7bedbef709447319ff0016d",
    );
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
fn identity_hard_derivation() {
    key_gen_test(
        KeyContext::Identity,
        1,
        0,
        "232847ae1bb95babcaa50c8033fab98f59e4b4ad1d89ac523a90c830e4ceee4a",
    );

    key_gen_test(
        KeyContext::Identity,
        2,
        1,
        "8f68b6572860d84e8a41e38db1c8c692ded5eb291846f2e5bbfde774a9c6d16e",
    );
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
fn bip32_ed25519_khovratovich_derive_address_0_0() {
    let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
    let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

    let bip44_path = [harden(44), harden(283), harden(0), 0, 0];

    let mut current_xprv = root_xprv.clone();
    for &index in &bip44_path {
        current_xprv = current_xprv.derive(DerivationScheme::V2, index);
    }

    let public_key = current_xprv.public().public_key();
    let expected_key_gen = key_gen(root_xprv, KeyContext::Address, 0, 0, DerivationScheme::V2)
        .public()
        .public_key();

    assert_eq!(
        public_key, expected_key_gen,
        "Khovratovich derivation should match key_gen"
    );
}

// Test: BIP32-Ed25519 derive key m'/44'/283'/0'/0/1 using Khovratovich (V2) scheme
#[test]
fn bip32_ed25519_khovratovich_derive_address_0_1() {
    let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
    let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

    let bip44_path = [harden(44), harden(283), harden(0), 0, 1];

    let mut current_xprv = root_xprv.clone();
    for &index in &bip44_path {
        current_xprv = current_xprv.derive(DerivationScheme::V2, index);
    }

    let public_key = current_xprv.public().public_key();
    let expected_key_gen = key_gen(root_xprv, KeyContext::Address, 0, 1, DerivationScheme::V2)
        .public()
        .public_key();

    assert_eq!(
        public_key, expected_key_gen,
        "Khovratovich derivation should match key_gen"
    );
}

// Test: BIP32-Ed25519 derive PUBLIC key m'/44'/283'/1'/0/1 using Khovratovich (V2) scheme
// it("(OK) BIP32-Ed25519 derive PUBLIC key m'/44'/283'/1'/0/1", async () => {
//     ...
// })
#[test]
fn bip32_ed25519_khovratovich_derive_public_address_1_1() {
    let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
    let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

    let bip44_path_private = [harden(44), harden(283), harden(1), 0, 1];

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

    let expected_key_gen = key_gen(root_xprv, KeyContext::Address, 1, 1, DerivationScheme::V2)
        .public()
        .public_key();

    assert_eq!(
        derived_pub, expected_key_gen,
        "Public derivation should match private derivation"
    );
}

// Test: BIP32-Ed25519 derive PUBLIC key m'/44'/0'/1'/0/2 using Khovratovich (V2) scheme
#[test]
fn bip32_ed25519_khovratovich_derive_public_identity_1_2() {
    let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
    let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

    let bip44_path_private = [harden(44), harden(0), harden(1), 0, 2];

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

    let expected_key_gen = key_gen(root_xprv, KeyContext::Identity, 1, 2, DerivationScheme::V2)
        .public()
        .public_key();

    assert_eq!(
        derived_pub, expected_key_gen,
        "Public derivation should match private derivation"
    );
}

// Test: Sign and verify a message
#[test]
fn sign_and_verify_message() {
    let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
    let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

    let message = b"Hello, World!";

    let xprv = key_gen(
        root_xprv,
        KeyContext::Address,
        0,
        0,
        DerivationScheme::Peikert,
    );
    let xpub = xprv.public();

    let signature: Signature<Vec<u8>> = xprv.sign(message);

    assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
    assert!(
        xpub.verify(message, &signature),
        "Signature should be valid"
    );
}

// Test: Sign transaction
// it("(OK) Sign Transaction", async () => {
//     const key: Uint8Array = await cryptoService.keyGen(rootKey, KeyContext.Address, 0, 0, BIP32DerivationType.Khovratovich)
//     const prefixEncodedTx = new Uint8Array(Buffer.from('VFiJo2FtdM0D6KNmZWXNA+iiZnbOAkeSd6NnZW6sdGVzdG5ldC12MS4womhoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds4CR5Zfo3JjdsQgYv6DK3rRBUS+gzemcENeUGSuSmbne9eJCXZbRrV2pvOjc25kxCBi/oMretEFRL6DN6ZwQ15QZK5KZud714kJdltGtXam86R0eXBlo3BheQ==', 'base64'))
//     const sig = await cryptoService.signAlgoTransaction(rootKey, KeyContext.Address, 0, 0, prefixEncodedTx, BIP32DerivationType.Khovratovich)
//     expect(nacl.sign.detached.verify(prefixEncodedTx, sig, key)).toBe(true)
// })
#[test]
fn sign_transaction() {
    let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
    let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

    let xprv = key_gen(
        root_xprv.clone(),
        KeyContext::Address,
        0,
        0,
        DerivationScheme::V2,
    );
    let xpub = xprv.public();

    let prefix_encoded_tx = base64_decode("VFiJo2FtdM0D6KNmZWXNA+iiZnbOAkeSd6NnZW6sdGVzdG5ldC12MS4womhoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds4CR5Zfo3JjdsQgYv6DK3rRBUS+gzemcENeUGSuSmbne9eJCXZbRrV2pvOjc25kxCBi/oMretEFRL6DN6ZwQ15QZK5KZud714kJdltGtXam86R0eXBlo3BheQ==");

    let sig = sign(
        &root_xprv,
        KeyContext::Address,
        0,
        0,
        &prefix_encoded_tx,
        DerivationScheme::V2,
    );

    assert_eq!(sig.len(), 64, "Signature should be 64 bytes");
    assert!(
        xpub.verify(
            &prefix_encoded_tx,
            &Signature::<u8>::from_slice(&sig).unwrap()
        ),
        "Signature should be valid for the transaction"
    );
}

// Test: deriveNodePublic - derive N keys with only public information
// it("(OK) From m'/44'/283'/0'/0 root level derive N keys with only public information", async () => {
//     ...
// })
#[test]
fn derive_node_public_soft_derivation() {
    let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
    let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

    let wallet_root_path = [harden(44), harden(283), harden(0), 0];

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
            root_xprv.clone(),
            KeyContext::Address,
            0,
            i,
            DerivationScheme::Peikert,
        )
        .public()
        .public_key();

        assert_eq!(
            derived_xpub.public_key(),
            my_key,
            "Public derivation at index {} should match private derivation",
            i
        );
    }
}

// Test: deriveNodePublic - should NOT derive correct addresses from hardened root
// it("(FAIL) From m'/44'/283'/0'/0' root level should not be able to derive correct addresses from a hardened derivation", async () => {
//     ...
// })
#[test]
fn derive_node_public_hard_derivation_mismatch() {
    let root_key_bytes = hex_to_bytes(ROOT_KEY_HEX);
    let root_xprv = XPrv::from_slice_verified(&root_key_bytes).unwrap();

    let wallet_root_path = [harden(44), harden(283), harden(0), harden(0)];

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
            root_xprv.clone(),
            KeyContext::Address,
            0,
            i,
            DerivationScheme::Peikert,
        )
        .public()
        .public_key();

        assert_ne!(
            derived_xpub.public_key(),
            my_key,
            "Public derivation from hardened root should NOT match private derivation at index {}",
            i
        );
    }
}
