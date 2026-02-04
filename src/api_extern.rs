use std::convert::{TryFrom, TryInto};

use bip39::{Mnemonic, Seed};

use crate::{api, XPrv};

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum ReturnCode {
    Success = 0,
    InvalidRootKey = 1,
    InvalidDerivationScheme = 2,
    InvalidLanguageCode = 3,
    InvalidUtf8 = 4,
}

fn xprv_from_ptr(ptr: *const u8) -> Result<XPrv, ()> {
    let slice = unsafe { std::slice::from_raw_parts(ptr, 96) };
    XPrv::from_slice_verified(slice).map_err(|_| ())
}

/// # Safety
/// * `root_xprv` must point to a 96 byte array
/// * `path` must point to an array of u32 of length `path_length`
/// * `derived_xprv_out` must point to a 96 byte array
///
/// # Returns
/// * `Success` (0) - Path derivation completed successfully
/// * `InvalidRootKey` (1) - The provided root key is invalid or not 96 bytes
/// * `InvalidDerivationScheme` (2) - The scheme value is not a valid derivation scheme
#[no_mangle]
pub unsafe extern "C" fn derive_path(
    root_xprv: *const u8,
    path: *const u32,
    path_length: usize,
    scheme: u8,
    derived_xprv_out: *mut u8,
) -> ReturnCode {
    let xprv = match xprv_from_ptr(root_xprv) {
        Ok(k) => k,
        Err(_) => return ReturnCode::InvalidRootKey,
    };

    let path_slice = std::slice::from_raw_parts(path, path_length);
    let scheme = match crate::DerivationScheme::try_from(scheme) {
        Ok(s) => s,
        Err(_) => return ReturnCode::InvalidDerivationScheme,
    };

    let derived_xprv = api::derive_path(&xprv, path_slice, scheme);
    let out_slice = std::slice::from_raw_parts_mut(derived_xprv_out, 96);
    out_slice.copy_from_slice(derived_xprv.as_ref());

    ReturnCode::Success
}

/// # Safety
/// * `root_xprv` must point to a 96 byte array
/// * `derived_xprv_out` must point to a 96 byte array
///
/// # Returns
/// * `Success` (0) - Key generation completed successfully
/// * `InvalidRootKey` (1) - The provided root key is invalid or not 96 bytes
/// * `InvalidDerivationScheme` (2) - The context or scheme value is not valid
#[no_mangle]
pub unsafe extern "C" fn key_gen(
    root_xprv: *const u8,
    context: u32,
    account: u32,
    key_index: u32,
    scheme: u8,
    derived_xprv_out: *mut u8,
) -> ReturnCode {
    let xprv = match xprv_from_ptr(root_xprv) {
        Ok(k) => k,
        Err(_) => return ReturnCode::InvalidRootKey,
    };

    let key_context = match context {
        0 => api::KeyContext::Address,
        1 => api::KeyContext::Identity,
        _ => return ReturnCode::InvalidDerivationScheme,
    };

    let scheme = match crate::DerivationScheme::try_from(scheme) {
        Ok(s) => s,
        Err(_) => return ReturnCode::InvalidDerivationScheme,
    };

    let derived_xprv = api::key_gen(&xprv, key_context, account, key_index, scheme);

    let out_slice = std::slice::from_raw_parts_mut(derived_xprv_out, 96);
    out_slice.copy_from_slice(derived_xprv.as_ref());

    ReturnCode::Success
}

/// # Safety
/// * `root_xprv` must point to a 96 byte array
/// * `bip44_path` must point to an array of u32 of length `path_length`
/// * `data` must point to an array of u8 of length `data_length`
/// * `signature_out` must point to an array of u8 of sufficient length to hold the signature
///
/// # Returns
/// * `Success` (0) - Signing completed successfully
/// * `InvalidRootKey` (1) - The provided root key is invalid or not 96 bytes
/// * `InvalidDerivationScheme` (2) - The scheme value is not a valid derivation scheme
#[no_mangle]
pub unsafe extern "C" fn raw_sign(
    root_xprv: *const u8,
    bip44_path: *const u32,
    path_length: usize,
    data: *const u8,
    data_length: usize,
    scheme: u8,
    signature_out: *mut u8,
) -> ReturnCode {
    let xprv = match xprv_from_ptr(root_xprv) {
        Ok(k) => k,
        Err(_) => return ReturnCode::InvalidRootKey,
    };

    let path_slice = std::slice::from_raw_parts(bip44_path, path_length);
    let data_slice = std::slice::from_raw_parts(data, data_length);

    let scheme = match crate::DerivationScheme::try_from(scheme) {
        Ok(s) => s,
        Err(_) => return ReturnCode::InvalidDerivationScheme,
    };

    let signature_bytes = api::raw_sign(&xprv, path_slice, data_slice, scheme);
    let out_slice = std::slice::from_raw_parts_mut(signature_out, signature_bytes.len());
    out_slice.copy_from_slice(&signature_bytes);

    ReturnCode::Success
}

/// # Safety
/// * `root_xprv` must point to a 96 byte array
/// * `data` must point to an array of u8 of length `data_length`
/// * `signature_out` must point to an array of u8 of sufficient length to hold the signature
///
/// # Returns
/// * `Success` (0) - Signing completed successfully
/// * `InvalidRootKey` (1) - The provided root key is invalid or not 96 bytes
/// * `InvalidDerivationScheme` (2) - The context or scheme value is not valid
#[no_mangle]
pub unsafe extern "C" fn sign(
    root_xprv: *const u8,
    context: u32,
    account: u32,
    key_index: u32,
    data: *const u8,
    data_length: usize,
    scheme: u8,
    signature_out: *mut u8,
) -> ReturnCode {
    let xprv = match xprv_from_ptr(root_xprv) {
        Ok(k) => k,
        Err(_) => return ReturnCode::InvalidRootKey,
    };

    let data_slice = std::slice::from_raw_parts(data, data_length);

    let key_context = match context {
        0 => api::KeyContext::Address,
        1 => api::KeyContext::Identity,
        _ => return ReturnCode::InvalidDerivationScheme,
    };

    let scheme = match crate::DerivationScheme::try_from(scheme) {
        Ok(s) => s,
        Err(_) => return ReturnCode::InvalidDerivationScheme,
    };

    let signature_bytes = api::sign(&xprv, key_context, account, key_index, data_slice, scheme);
    let out_slice = std::slice::from_raw_parts_mut(signature_out, signature_bytes.len());
    out_slice.copy_from_slice(&signature_bytes);

    ReturnCode::Success
}

/// # Safety
/// * `seed` must point to a byte array of 64 bytes
/// * `root_xprv_out` must point to a byte array of 96 bytes
#[no_mangle]
pub extern "C" fn from_seed(seed: *const u8, root_xprv_out: *mut u8) {
    let seed_slice = unsafe { std::slice::from_raw_parts(seed, 64) };
    let root_xprv = XPrv::from_seed(seed_slice.try_into().unwrap());
    let out_slice = unsafe { std::slice::from_raw_parts_mut(root_xprv_out, 96) };
    out_slice.copy_from_slice(root_xprv.as_ref());
}

/// # Safety
/// * `mnemonic` must point to a UTF-8 encoded byte array of length `mnemonic_length`
/// * `seed_out` must point to a byte array of 64 bytes
/// * `lang_code` must point to a UTF-8 encoded byte array of length `lang_code_length`
/// * `passphrase` must point to a UTF-8 encoded byte array of length `passphrase_length` (can be zero)
///
/// # Returns
/// * `Success` (0) - Seed generation completed successfully
/// * `InvalidUtf8` (4) - The mnemonic, language code, or passphrase contains invalid UTF-8
/// * `InvalidLanguageCode` (3) - The language code is not recognized or the mnemonic is invalid for the language
///
/// # Language Codes
/// * "en" - English
/// * "zh-hans" - Chinese Simplified
/// * "zh-hant" - Chinese Traditional
/// * "fr" - French
/// * "it" - Italian
/// * "ja" - Japanese
/// * "ko" - Korean
/// * "es" - Spanish
#[no_mangle]
pub extern "C" fn seed_from_mnemonic(
    mnemonic: *const u8,
    mnemonic_length: usize,
    seed_out: *mut u8,
    lang_code: *const u8,
    lang_code_length: usize,
    passphrase: *const u8,
    passphrase_length: usize,
) -> ReturnCode {
    let mnemonic_slice = unsafe { std::slice::from_raw_parts(mnemonic, mnemonic_length) };
    let mnemonic_str = match std::str::from_utf8(mnemonic_slice) {
        Ok(s) => s,
        Err(_) => return ReturnCode::InvalidUtf8,
    };

    let lang_code_slice = unsafe { std::slice::from_raw_parts(lang_code, lang_code_length) };
    let lang_code_str = match std::str::from_utf8(lang_code_slice) {
        Ok(s) => s,
        Err(_) => return ReturnCode::InvalidUtf8,
    };

    let language = match bip39::Language::from_language_code(lang_code_str) {
        Some(lang) => lang,
        None => return ReturnCode::InvalidLanguageCode,
    };

    let mnemonic = match Mnemonic::from_phrase(mnemonic_str, language) {
        Ok(mnemonic) => mnemonic,
        Err(_) => return ReturnCode::InvalidLanguageCode,
    };

    let password = if passphrase_length > 0 {
        let passphrase_slice = unsafe { std::slice::from_raw_parts(passphrase, passphrase_length) };
        match std::str::from_utf8(passphrase_slice) {
            Ok(s) => s,
            Err(_) => return ReturnCode::InvalidUtf8,
        }
    } else {
        ""
    };

    let seed = Seed::new(&mnemonic, password);
    let seed_bytes = seed.as_bytes();

    let out_slice = unsafe { std::slice::from_raw_parts_mut(seed_out, 64) };
    out_slice.copy_from_slice(seed_bytes);

    ReturnCode::Success
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str = "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice";
    const SEED_HEX: &str = "3aff2db416b895ec3cf9a4f8d1e970bc9819920e7bf44a5e350477af0ef557b1511b0986debf78dd38c7c520cd44ff7c7231618f958e21ef0250733a8c1915ea";
    const ROOT_KEY_HEX: &str = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_seed_from_mnemonic() {
        let mut seed_out = [0u8; 64];
        let lang_code = b"en";
        let result = seed_from_mnemonic(
            MNEMONIC.as_ptr(),
            MNEMONIC.len(),
            seed_out.as_mut_ptr(),
            lang_code.as_ptr(),
            lang_code.len(),
            std::ptr::null(),
            0,
        );

        assert_eq!(result, ReturnCode::Success);
        assert_eq!(seed_out, hex_to_bytes(SEED_HEX).as_slice());
    }

    #[test]
    fn test_from_seed() {
        let mut root_xprv_out = [0u8; 96];

        let seed_bytes = hex_to_bytes(SEED_HEX);
        from_seed(seed_bytes.as_ptr(), root_xprv_out.as_mut_ptr());

        assert_eq!(root_xprv_out, hex_to_bytes(ROOT_KEY_HEX).as_slice());
    }

    #[test]
    fn test_derive_path_success() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let path: [u32; 5] = [0x8000002c, 0x8000011b, 0x80000000, 0, 0];
        let mut derived_xprv_out = [0u8; 96];

        unsafe {
            let result = derive_path(
                root_key.as_ptr(),
                path.as_ptr(),
                path.len(),
                1,
                derived_xprv_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::Success);
        }
    }

    #[test]
    fn test_derive_path_invalid_root_key() {
        let invalid_root_key = [0u8; 96];
        let path: [u32; 5] = [0x8000002c, 0x8000011b, 0x80000000, 0, 0];
        let mut derived_xprv_out = [0u8; 96];

        unsafe {
            let result = derive_path(
                invalid_root_key.as_ptr(),
                path.as_ptr(),
                path.len(),
                1,
                derived_xprv_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::InvalidRootKey);
        }
    }

    #[test]
    fn test_derive_path_invalid_scheme() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let path: [u32; 5] = [0x8000002c, 0x8000011b, 0x80000000, 0, 0];
        let mut derived_xprv_out = [0u8; 96];

        unsafe {
            let result = derive_path(
                root_key.as_ptr(),
                path.as_ptr(),
                path.len(),
                99,
                derived_xprv_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::InvalidDerivationScheme);
        }
    }

    #[test]
    fn test_key_gen_success_address() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let mut derived_xprv_out = [0u8; 96];

        unsafe {
            let result = key_gen(root_key.as_ptr(), 0, 0, 0, 1, derived_xprv_out.as_mut_ptr());
            assert_eq!(result, ReturnCode::Success);
        }
    }

    #[test]
    fn test_key_gen_success_identity() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let mut derived_xprv_out = [0u8; 96];

        unsafe {
            let result = key_gen(root_key.as_ptr(), 1, 0, 0, 1, derived_xprv_out.as_mut_ptr());
            assert_eq!(result, ReturnCode::Success);
        }
    }

    #[test]
    fn test_key_gen_invalid_root_key() {
        let invalid_root_key = [0u8; 96];
        let mut derived_xprv_out = [0u8; 96];

        unsafe {
            let result = key_gen(
                invalid_root_key.as_ptr(),
                0,
                0,
                0,
                1,
                derived_xprv_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::InvalidRootKey);
        }
    }

    #[test]
    fn test_key_gen_invalid_context() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let mut derived_xprv_out = [0u8; 96];

        unsafe {
            let result = key_gen(
                root_key.as_ptr(),
                99,
                0,
                0,
                1,
                derived_xprv_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::InvalidDerivationScheme);
        }
    }

    #[test]
    fn test_key_gen_invalid_scheme() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let mut derived_xprv_out = [0u8; 96];

        unsafe {
            let result = key_gen(
                root_key.as_ptr(),
                0,
                0,
                0,
                99,
                derived_xprv_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::InvalidDerivationScheme);
        }
    }

    #[test]
    fn test_raw_sign_success() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let bip44_path: [u32; 5] = [0x8000002c, 0x8000011b, 0x80000000, 0, 0];
        let data = b"Hello World";
        let mut signature_out = [0u8; 64];

        unsafe {
            let result = raw_sign(
                root_key.as_ptr(),
                bip44_path.as_ptr(),
                bip44_path.len(),
                data.as_ptr(),
                data.len(),
                1,
                signature_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::Success);
        }
    }

    #[test]
    fn test_raw_sign_invalid_root_key() {
        let invalid_root_key = [0u8; 96];
        let bip44_path: [u32; 5] = [0x8000002c, 0x8000011b, 0x80000000, 0, 0];
        let data = b"Hello World";
        let mut signature_out = [0u8; 64];

        unsafe {
            let result = raw_sign(
                invalid_root_key.as_ptr(),
                bip44_path.as_ptr(),
                bip44_path.len(),
                data.as_ptr(),
                data.len(),
                1,
                signature_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::InvalidRootKey);
        }
    }

    #[test]
    fn test_raw_sign_invalid_scheme() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let bip44_path: [u32; 5] = [0x8000002c, 0x8000011b, 0x80000000, 0, 0];
        let data = b"Hello World";
        let mut signature_out = [0u8; 64];

        unsafe {
            let result = raw_sign(
                root_key.as_ptr(),
                bip44_path.as_ptr(),
                bip44_path.len(),
                data.as_ptr(),
                data.len(),
                99,
                signature_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::InvalidDerivationScheme);
        }
    }

    #[test]
    fn test_sign_success() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let data = b"Hello World";
        let mut signature_out = [0u8; 64];

        unsafe {
            let result = sign(
                root_key.as_ptr(),
                0,
                0,
                0,
                data.as_ptr(),
                data.len(),
                1,
                signature_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::Success);
        }
    }

    #[test]
    fn test_sign_invalid_root_key() {
        let invalid_root_key = [0u8; 96];
        let data = b"Hello World";
        let mut signature_out = [0u8; 64];

        unsafe {
            let result = sign(
                invalid_root_key.as_ptr(),
                0,
                0,
                0,
                data.as_ptr(),
                data.len(),
                1,
                signature_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::InvalidRootKey);
        }
    }

    #[test]
    fn test_sign_invalid_context() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let data = b"Hello World";
        let mut signature_out = [0u8; 64];

        unsafe {
            let result = sign(
                root_key.as_ptr(),
                99,
                0,
                0,
                data.as_ptr(),
                data.len(),
                1,
                signature_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::InvalidDerivationScheme);
        }
    }

    #[test]
    fn test_sign_invalid_scheme() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let data = b"Hello World";
        let mut signature_out = [0u8; 64];

        unsafe {
            let result = sign(
                root_key.as_ptr(),
                0,
                0,
                0,
                data.as_ptr(),
                data.len(),
                99,
                signature_out.as_mut_ptr(),
            );
            assert_eq!(result, ReturnCode::InvalidDerivationScheme);
        }
    }

    #[test]
    fn test_derive_path_matches_internal_api() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let path: [u32; 5] = [0x8000002c, 0x8000011b, 0x80000000, 0, 0];
        let mut derived_xprv_out = [0u8; 96];

        let root_xprv = XPrv::from_slice_verified(&root_key).unwrap();
        let expected = api::derive_path(&root_xprv, &path, crate::DerivationScheme::Peikert);

        unsafe {
            derive_path(
                root_key.as_ptr(),
                path.as_ptr(),
                path.len(),
                1,
                derived_xprv_out.as_mut_ptr(),
            );
        }

        assert_eq!(derived_xprv_out, expected.as_ref());
    }

    #[test]
    fn test_key_gen_matches_internal_api() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let mut derived_xprv_out = [0u8; 96];

        let root_xprv = XPrv::from_slice_verified(&root_key).unwrap();
        let expected = api::key_gen(
            &root_xprv,
            api::KeyContext::Address,
            0,
            0,
            crate::DerivationScheme::Peikert,
        );

        unsafe {
            key_gen(root_key.as_ptr(), 0, 0, 0, 1, derived_xprv_out.as_mut_ptr());
        }

        assert_eq!(derived_xprv_out, expected.as_ref());
    }

    #[test]
    fn test_raw_sign_matches_internal_api() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let bip44_path: [u32; 5] = [0x8000002c, 0x8000011b, 0x80000000, 0, 0];
        let data = b"Hello World";
        let mut signature_out = [0u8; 64];

        let root_xprv = XPrv::from_slice_verified(&root_key).unwrap();
        let expected = api::raw_sign(
            &root_xprv,
            &bip44_path,
            data,
            crate::DerivationScheme::Peikert,
        );

        unsafe {
            raw_sign(
                root_key.as_ptr(),
                bip44_path.as_ptr(),
                bip44_path.len(),
                data.as_ptr(),
                data.len(),
                1,
                signature_out.as_mut_ptr(),
            );
        }

        assert_eq!(signature_out.to_vec(), expected);
    }

    #[test]
    fn test_sign_matches_internal_api() {
        let root_key = hex_to_bytes(ROOT_KEY_HEX);
        let data = b"Hello World";
        let mut signature_out = [0u8; 64];

        let root_xprv = XPrv::from_slice_verified(&root_key).unwrap();
        let expected = api::sign(
            &root_xprv,
            api::KeyContext::Address,
            0,
            0,
            data,
            crate::DerivationScheme::Peikert,
        );

        unsafe {
            sign(
                root_key.as_ptr(),
                0,
                0,
                0,
                data.as_ptr(),
                data.len(),
                1,
                signature_out.as_mut_ptr(),
            );
        }

        assert_eq!(signature_out.to_vec(), expected);
    }
}
