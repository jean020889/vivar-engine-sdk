#![crate_type = "cdylib"]

use std::slice;
use zeroize::Zeroize;
use pqcrypto_kyber::kyber768::{encapsulate, keypair, PublicKey};
use pqcrypto_traits::kem::{PublicKey as PkTrait, SecretKey as SkTrait, Ciphertext as CtTrait, SharedSecret as SsTrait};
use hkdf::Hkdf;
use sha2::Sha256;

#[repr(i32)]
pub enum VceError {
    Success = 0,
    NullPointer = 1,
    CryptoError = 3,
}

#[repr(C)]
pub struct VivarBuffer {
    pub data: *mut u8,
    pub len: usize,
}

fn vivar_diffusion_operator(data: &mut [u8], key: &[u8], is_encrypt: bool) {
    let mut feedback: u64 = 0x9E3779B9;
    let key_len = key.len();

    for (i, val) in data.iter_mut().enumerate() {
        let key_byte = key[i % key_len] as u64;
        let nonce = (i & 0xFF) as u64;
        let transformation = (feedback ^ nonce ^ key_byte).rotate_left(7);
        
        if is_encrypt {
            *val ^= (transformation & 0xFF) as u8;
            feedback = *val as u64 ^ feedback.rotate_right(3);
        } else {
            let original = *val;
            *val ^= (transformation & 0xFF) as u8;
            feedback = original as u64 ^ feedback.rotate_right(3);
        }
    }
}

/// RENOMBRADA para coincidir con tu client.py: vivar_operator_engine
#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    buffer: *mut VivarBuffer,
    key_ptr: *mut u8,
    key_len: usize
) -> i32 {
    if buffer.is_null() || key_ptr.is_null() { return VceError::NullPointer as i32; }
    
    unsafe {
        let buf = &mut *buffer;
        let data_slice = slice::from_raw_parts_mut(buf.data, buf.len);
        let key_slice = slice::from_raw_parts(key_ptr, key_len);
        
        // Asumimos cifrado por defecto al ser el motor de mutación
        vivar_diffusion_operator(data_slice, key_slice, true);
        
        let mut mut_key = slice::from_raw_parts_mut(key_ptr, key_len);
        mut_key.zeroize();
    }
    VceError::Success as i32
}

// ... (mantén tus funciones generate_pqc_keys y perform_kem_encapsulation igual)
