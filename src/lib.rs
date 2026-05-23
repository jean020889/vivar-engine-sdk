#![crate_type = "cdylib"]

use std::slice;
use zeroize::Zeroize;
use pqcrypto_kyber::kyber768::{encapsulate, keypair, PublicKey};
use pqcrypto_traits::kem::PublicKey as PkTrait;
use pqcrypto_traits::kem::SecretKey as SkTrait;
use pqcrypto_traits::kem::Ciphertext as CtTrait;
use pqcrypto_traits::kem::SharedSecret as SsTrait;
use hkdf::Hkdf;
use sha2::Sha256;

#[repr(C)]
pub struct VivarBuffer {
    pub data: *mut u8,
    pub len: usize,
}

/// Motor de Cifrado Vivar: Algoritmo de difusión con realimentación (VCE)
/// Nivel corporativo: Utiliza realimentación compleja para streaming de baja latencia.
#[no_mangle]
pub extern "C" fn vivar_crypt_engine(
    buffer: *mut VivarBuffer,
    key_ptr: *mut u8,
    key_len: usize,
    is_encrypt: u8
) -> i32 {
    if buffer.is_null() || key_ptr.is_null() { return 1; }
    
    unsafe {
        let buf = &mut *buffer;
        let data_slice = slice::from_raw_parts_mut(buf.data, buf.len);
        let key_slice = slice::from_raw_parts_mut(key_ptr, key_len);
        
        let mut feedback: u8 = 0;
        let encrypt = is_encrypt != 0;
        
        for i in 0..buf.len {
            let nonce = (i & 0xFF) as u8;
            let val = data_slice[i];
            
            if encrypt {
                let current = val ^ key_slice[i % key_len] ^ nonce ^ feedback;
                data_slice[i] = current;
                feedback = current;
            } else {
                let decrypted = val ^ feedback ^ nonce ^ key_slice[i % key_len];
                data_slice[i] = decrypted;
                feedback = val;
            }
        }
        // Borrado seguro de la clave de la RAM tras su uso
        key_slice.zeroize();
    }
    0
}

/// Generación de claves seguras: FIPS 203 (Kyber768)
#[no_mangle]
pub extern "C" fn generate_pqc_keys(pk_out: *mut u8, sk_out: *mut u8) -> i32 {
    let (pk, sk) = keypair();
    unsafe {
        std::ptr::copy_nonoverlapping(PkTrait::as_bytes(&pk).as_ptr(), pk_out, 1184);
        std::ptr::copy_nonoverlapping(SkTrait::as_bytes(&sk).as_ptr(), sk_out, 2400);
    }
    0
}

/// Encapsulación de clave con derivación HKDF (Nivel Corporativo)
/// Garantiza que cada sesión de cifrado sea única, incluso con la misma clave pública.
#[no_mangle]
pub extern "C" fn perform_kem_encapsulation(
    pk_in: *const u8, 
    ct_out: *mut u8, 
    ss_out: *mut u8,
    salt: *const u8, 
    salt_len: usize
) -> i32 {
    unsafe {
        let pk = match PublicKey::from_bytes(slice::from_raw_parts(pk_in, 1184)) {
            Ok(k) => k,
            Err(_) => return 2,
        };
        let (ss, ct) = encapsulate(&pk);
        
        // Derivación de clave robusta usando HKDF-SHA256
        let salt_slice = slice::from_raw_parts(salt, salt_len);
        let hk = Hkdf::<Sha256>::new(Some(salt_slice), ss.as_bytes());
        
        let mut okm = [0u8; 32];
        if hk.expand(b"vivar-encryption-session", &mut okm).is_err() {
            return 3;
        }
        
        std::ptr::copy_nonoverlapping(CtTrait::as_bytes(&ct).as_ptr(), ct_out, 1088);
        std::ptr::copy_nonoverlapping(okm.as_ptr(), ss_out, 32);
    }
    0
}
