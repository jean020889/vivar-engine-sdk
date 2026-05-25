#![crate_type = "cdylib"]

use zeroize::Zeroize;
use pqcrypto_kyber::kyber768::{keypair, encapsulate, decapsulate, Ciphertext, PublicKey, SecretKey};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use std::slice;

// --- MÓDULO VIVAR KERNEL ---
const VIVAR_SPECTRAL_CONSTANT: [u8; 32] = [
    0x4A, 0x1B, 0x8C, 0x3D, 0x9E, 0x2F, 0x50, 0x61, 
    0x72, 0x83, 0x94, 0xA5, 0xB6, 0xC7, 0xD8, 0xE9,
    0xFA, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x5A, 0x6B,
    0x7C, 0x8D, 0x9E, 0xAF, 0xB0, 0xC1, 0xD2, 0xE3
];

const VIVAR_SECRET_SALT: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
];

const KYBER_CT_SIZE: usize = 1088;
const SECRET_SIZE: usize = 2400;

#[repr(C)]
pub struct PqcVault {
    pub ciphertext: [u8; KYBER_CT_SIZE],
    pub encrypted_payload: [u8; SECRET_SIZE],
}

fn derive_hardened_key(session_key_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VIVAR_SPECTRAL_CONSTANT);
    hasher.update(VIVAR_SECRET_SALT);
    hasher.update(session_key_bytes);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct SessionKey([u8; 32]);

// --- FUNCIONES EXPORTADAS ---

#[no_mangle]
pub extern "C" fn generate_keys(pk_ptr: *mut u8, sk_ptr: *mut u8) {
    let (pk, sk) = keypair();
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_bytes().as_ptr(), pk_ptr, 1184);
        std::ptr::copy_nonoverlapping(sk.as_bytes().as_ptr(), sk_ptr, 2400);
    }
}

#[no_mangle]
pub extern "C" fn seal_secret(pk_ptr: *const u8, sk_ptr: *const u8, vault_ptr: *mut PqcVault) -> i32 {
    unsafe {
        if pk_ptr.is_null() || sk_ptr.is_null() || vault_ptr.is_null() { return 1; }
        
        let pk = match PublicKey::from_bytes(slice::from_raw_parts(pk_ptr, 1184)) {
            Ok(p) => p, Err(_) => return 2 
        };
        
        let (ct, ss) = encapsulate(&pk);
        let sk_raw = slice::from_raw_parts(sk_ptr, SECRET_SIZE);
        let mut encrypted_sk = [0u8; SECRET_SIZE];
        
        for i in 0..SECRET_SIZE {
            encrypted_sk[i] = sk_raw[i] ^ ss.as_bytes()[i % 32];
        }
        
        let vault = &mut *vault_ptr;
        // Copia explícita y segura por rangos para evitar desbordamientos
        vault.ciphertext[..KYBER_CT_SIZE].copy_from_slice(ct.as_bytes());
        vault.encrypted_payload.copy_from_slice(&encrypted_sk);
    }
    0
}

#[no_mangle]
pub extern "C" fn vivar_pqc_process(
    data: *mut u8, len: usize,
    ciphertext: *const u8, ct_len: usize,
    secret_key: *const u8, sk_len: usize
) -> i32 {
    if data.is_null() || ciphertext.is_null() || secret_key.is_null() || len == 0 { return 1; }
    unsafe {
        let ct_bytes = slice::from_raw_parts(ciphertext, ct_len);
        let sk_bytes = slice::from_raw_parts(secret_key, sk_len);
        let ct = match Ciphertext::from_bytes(ct_bytes) { Ok(c) => c, Err(_) => return 2 };
        let sk = match SecretKey::from_bytes(sk_bytes) { Ok(s) => s, Err(_) => return 3 };
        
        let ss = decapsulate(&ct, &sk);
        let hk = Hkdf::<Sha256>::new(None, ss.as_bytes());
        let mut raw_key = [0u8; 32];
        
        if hk.expand(b"VIVAR_INDUSTRIAL_PQC_KEY_2026", &mut raw_key).is_err() { return 4; }
        
        let hardened_key = derive_hardened_key(&raw_key);
        let mut session_key = SessionKey(hardened_key);
        let data_slice = slice::from_raw_parts_mut(data, len);
        
        for i in 0..len {
            let key_byte = session_key.0[i % 32];
            let mut val = (i as u64) ^ 0x5A5A5A5A5A5A5A5A;
            val = val.wrapping_mul(0xbf58476d1ce4e5b9);
            val ^= val >> 32;
            let mask = val as u8;
            data_slice[i] ^= key_byte ^ mask;
        }
        session_key.zeroize();
    }
    0
}
