#![crate_type = "cdylib"]

use std::slice;
use zeroize::Zeroize;
use pqcrypto_kyber::kyber768::{encapsulate, keypair, PublicKey};
use pqcrypto_traits::kem::{PublicKey as PkTrait, SecretKey as SkTrait, Ciphertext as CtTrait, SharedSecret as SsTrait};
use hkdf::Hkdf;
use sha2::Sha256;
use hmac::{Hmac, Mac};

// --- Definiciones del Motor Vivar ---

#[repr(i32)]
pub enum VceError {
    Success = 0,
    NullPointer = 1,
    IntegrityError = 2,
    CryptoError = 3,
}

#[repr(C)]
pub struct VivarBuffer {
    pub data: *mut u8,
    pub len: usize,
}

/// Implementación del Operador de Difusión Vivar (VCE)
/// Emula la rigidez espectral eliminando fugas mediante realimentación.
fn vivar_diffusion_operator(data: &mut [u8], key: &[u8], is_encrypt: bool) {
    let mut feedback: u64 = 0x9E3779B9; // Constante de dispersión adélica
    let key_len = key.len();

    for (i, val) in data.iter_mut().enumerate() {
        let key_byte = key[i % key_len] as u64;
        let nonce = (i & 0xFF) as u64;
        
        // Operación de difusión no lineal
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

/// Motor de Cifrado Vivar: Interfaz C exportable
#[no_mangle]
pub extern "C" fn vivar_crypt_engine(
    buffer: *mut VivarBuffer,
    key_ptr: *mut u8,
    key_len: usize,
    is_encrypt: u8
) -> i32 {
    if buffer.is_null() || key_ptr.is_null() { return VceError::NullPointer as i32; }
    
    unsafe {
        let buf = &mut *buffer;
        let data_slice = slice::from_raw_parts_mut(buf.data, buf.len);
        let key_slice = slice::from_raw_parts(key_ptr, key_len);
        
        vivar_diffusion_operator(data_slice, key_slice, is_encrypt != 0);
        
        // Limpieza de memoria sensible
        let mut mut_key = slice::from_raw_parts_mut(key_ptr, key_len);
        mut_key.zeroize();
    }
    VceError::Success as i32
}

/// Generación de claves seguras: FIPS 203 (Kyber768)
#[no_mangle]
pub extern "C" fn generate_pqc_keys(pk_out: *mut u8, sk_out: *mut u8) -> i32 {
    if pk_out.is_null() || sk_out.is_null() { return 1; }
    
    let (pk, sk) = keypair();
    unsafe {
        std::ptr::copy_nonoverlapping(PkTrait::as_bytes(&pk).as_ptr(), pk_out, 1184);
        std::ptr::copy_nonoverlapping(SkTrait::as_bytes(&sk).as_ptr(), sk_out, 2400);
    }
    VceError::Success as i32
}

/// Encapsulación con derivación HKDF para el motor
#[no_mangle]
pub extern "C" fn perform_kem_encapsulation(
    pk_in: *const u8, 
    ct_out: *mut u8, 
    ss_out: *mut u8,
    salt: *const u8, 
    salt_len: usize
) -> i32 {
    if pk_in.is_null() || ct_out.is_null() || ss_out.is_null() || salt.is_null() {
        return VceError::NullPointer as i32;
    }
    
    unsafe {
        let pk = match PublicKey::from_bytes(slice::from_raw_parts(pk_in, 1184)) {
            Ok(k) => k,
            Err(_) => return VceError::CryptoError as i32,
        };
        let (ss, ct) = encapsulate(&pk);
        
        let salt_slice = slice::from_raw_parts(salt, salt_len);
        let hk = Hkdf::<Sha256>::new(Some(salt_slice), ss.as_bytes());
        
        let mut okm = [0u8; 32];
        if hk.expand(b"vivar-encryption-session", &mut okm).is_err() {
            return VceError::CryptoError as i32;
        }
        
        std::ptr::copy_nonoverlapping(CtTrait::as_bytes(&ct).as_ptr(), ct_out, 1088);
        std::ptr::copy_nonoverlapping(okm.as_ptr(), ss_out, 32);
    }
    VceError::Success as i32
}
