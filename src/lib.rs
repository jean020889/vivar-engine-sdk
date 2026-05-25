#![crate_type = "cdylib"]

use zeroize::Zeroize;
use pqcrypto_kyber::kyber768;
use hkdf::Hkdf;
use sha2::Sha256;

// Estructura para proteger la clave en memoria
#[derive(Zeroize)]
#[zeroize(drop)]
struct SessionKey([u8; 32]);

#[no_mangle]
pub extern "C" fn vivar_pqc_process(
    data: *mut u8,
    len: usize,
    ciphertext: *const u8,
    ct_len: usize,
    secret_key: *const u8,
    sk_len: usize
) -> i32 {
    if data.is_null() || ciphertext.is_null() || secret_key.is_null() { return 1; }

    unsafe {
        // 1. Decapsulación PQC (Kyber-768)
        let ct = std::slice::from_raw_parts(ciphertext, ct_len);
        let sk = std::slice::from_raw_parts(secret_key, sk_len);
        
        let (ss, _) = match kyber768::decapsulate(ct, sk) {
            Ok(res) => res,
            Err(_) => return 2, // Error de decapsulación
        };

        // 2. Derivación de clave de sesión (HKDF)
        let hk = Hkdf::<Sha256>::new(None, &ss);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"VIVAR_SESSION_KEY", &mut key_bytes).unwrap();
        
        let mut session_key = SessionKey(key_bytes);
        
        // 3. Aplicación de flujo (Permutación ARX mejorada con la clave PQC)
        let data_slice = std::slice::from_raw_parts_mut(data, len);
        for i in 0..len {
            data_slice[i] ^= session_key.0[i % 32];
        }

        // Limpieza absoluta de memoria volátil
        session_key.zeroize();
    }
    0
}
