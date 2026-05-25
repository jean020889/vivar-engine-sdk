#![crate_type = "cdylib"]

use zeroize::Zeroize;
use pqcrypto_kyber::kyber768::{keypair, encapsulate, decapsulate, Ciphertext, PublicKey, SecretKey};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use hkdf::Hkdf;
use sha2::Sha256;
use std::slice;

#[derive(Zeroize)]
#[zeroize(drop)]
struct SessionKey([u8; 32]);

#[no_mangle]
pub extern "C" fn generate_keys(pk_ptr: *mut u8, sk_ptr: *mut u8) {
    let (pk, sk) = keypair();
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_bytes().as_ptr(), pk_ptr, 1184);
        std::ptr::copy_nonoverlapping(sk.as_bytes().as_ptr(), sk_ptr, 2400);
    }
}

#[no_mangle]
pub extern "C" fn generate_ciphertext(pk_ptr: *const u8, ct_ptr: *mut u8) -> i32 {
    let pk_bytes = unsafe { slice::from_raw_parts(pk_ptr, 1184) };
    let pk = match PublicKey::from_bytes(pk_bytes) {
        Ok(p) => p,
        Err(_) => return 1,
    };
    let (ct, _) = encapsulate(&pk);
    unsafe {
        std::ptr::copy_nonoverlapping(ct.as_bytes().as_ptr(), ct_ptr, 1088);
    }
    0
}


#[no_mangle]
pub extern "C" fn get_version() -> i32 {
    // Retorna un entero (ej: 100 para v1.0.0, 101 para v1.0.1)
    100 
}


#[no_mangle]
pub extern "C" fn vivar_pqc_process(
    data: *mut u8, len: usize,
    ciphertext: *const u8, ct_len: usize,
    secret_key: *const u8, sk_len: usize
) -> i32 {
    if data.is_null() || ciphertext.is_null() || secret_key.is_null() || len == 0 {
        return 1;
    }

    unsafe {
        let ct_bytes = slice::from_raw_parts(ciphertext, ct_len);
        let sk_bytes = slice::from_raw_parts(secret_key, sk_len);

        let ct = match Ciphertext::from_bytes(ct_bytes) { Ok(c) => c, Err(_) => return 2 };
        let sk = match SecretKey::from_bytes(sk_bytes) { Ok(s) => s, Err(_) => return 3 };
        
        let ss = decapsulate(&ct, &sk);
        let hk = Hkdf::<Sha256>::new(None, ss.as_bytes());
        let mut key_bytes = [0u8; 32];
        
        if hk.expand(b"VIVAR_INDUSTRIAL_PQC_KEY_2026", &mut key_bytes).is_err() { return 4; }
        
        let mut session_key = SessionKey(key_bytes);
        let data_slice = slice::from_raw_parts_mut(data, len);
        
        // --- NÚCLEO CORREGIDO PARA INTEGRIDAD BINARIA ---
        for i in 0..len {
            let key_byte = session_key.0[i % 32];
            // Generación de máscara independiente para asegurar reversibilidad bit-perfect
            let mut val = (i as u64) ^ 0x5A5A5A5A5A5A5A5A;
            val = val.wrapping_mul(0xbf58476d1ce4e5b9);
            val ^= val >> 32;
            let mask = (val as u8);
            
            data_slice[i] ^= key_byte ^ mask;
        }

        session_key.zeroize();
    }
    0
}
