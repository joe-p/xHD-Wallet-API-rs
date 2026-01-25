use std::convert::TryFrom;

use crate::{api, XPrv};

#[repr(u8)]
#[derive(Debug, PartialEq, Eq)]
pub enum ReturnCode {
    Success = 0,
    InvalidRootKey = 1,
    InvalidDerivationScheme = 2,
}

fn xprv_from_ptr(ptr: *const u8) -> Result<XPrv, ()> {
    let slice = unsafe { std::slice::from_raw_parts(ptr, 96) };
    XPrv::from_slice_verified(slice).map_err(|_| ())
}

/// # Safety
/// * `root_xprv` must point to a 96 byte array
/// * `path` must point to an array of u32 of length `path_length`
/// * `derived_xprv_out` must point to a 96 byte array
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

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ROOT_KEY: [u8; 96] = [
        0xf8, 0xa2, 0x92, 0x31, 0xee, 0x38, 0xd6, 0xc5, 0xbf, 0x71, 0x5d, 0x5b, 0xac, 0x21, 0xc7,
        0x50, 0x57, 0x7a, 0xa3, 0x79, 0x8b, 0x22, 0xd7, 0x9d, 0x65, 0xbf, 0x97, 0xd6, 0xfa, 0xde,
        0xa1, 0x5a, 0xdc, 0xd1, 0xee, 0x1a, 0xbd, 0xf7, 0x8b, 0xd4, 0xbe, 0x64, 0x73, 0x1a, 0x12,
        0xde, 0xb9, 0x4d, 0x36, 0x71, 0x78, 0x41, 0x12, 0xeb, 0x6f, 0x36, 0x4b, 0x87, 0x18, 0x51,
        0xfd, 0x1c, 0x9a, 0x24, 0x73, 0x84, 0xdb, 0x9a, 0xd6, 0x00, 0x3b, 0xbd, 0x08, 0xb3, 0xb1,
        0xdd, 0xc0, 0xd0, 0x7a, 0x59, 0x72, 0x93, 0xff, 0x85, 0xe9, 0x61, 0xbf, 0x25, 0x2b, 0x33,
        0x12, 0x62, 0xed, 0xdf, 0xad, 0x0d,
    ];

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_derive_path_success() {
        let root_key = VALID_ROOT_KEY;
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
        let root_key = VALID_ROOT_KEY;
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
        let root_key = VALID_ROOT_KEY;
        let mut derived_xprv_out = [0u8; 96];

        unsafe {
            let result = key_gen(root_key.as_ptr(), 0, 0, 0, 1, derived_xprv_out.as_mut_ptr());
            assert_eq!(result, ReturnCode::Success);
        }
    }

    #[test]
    fn test_key_gen_success_identity() {
        let root_key = VALID_ROOT_KEY;
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
        let root_key = VALID_ROOT_KEY;
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
        let root_key = VALID_ROOT_KEY;
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
        let root_key_hex = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";
        let root_key = hex_to_bytes(root_key_hex);
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
        let root_key_hex = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";
        let root_key = hex_to_bytes(root_key_hex);
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
        let root_key_hex = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";
        let root_key = hex_to_bytes(root_key_hex);
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
        let root_key_hex = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";
        let root_key = hex_to_bytes(root_key_hex);
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
        let root_key_hex = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";
        let root_key = hex_to_bytes(root_key_hex);
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
        let root_key_hex = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";
        let root_key = hex_to_bytes(root_key_hex);
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
        let root_key_hex = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";
        let root_key = hex_to_bytes(root_key_hex);
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
        let root_key_hex = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";
        let root_key = hex_to_bytes(root_key_hex);
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
        let root_key_hex = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";
        let root_key = hex_to_bytes(root_key_hex);
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
