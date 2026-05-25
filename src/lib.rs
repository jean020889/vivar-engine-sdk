#![crate_type = "cdylib"]

use zeroize::Zeroize;
use pqcrypto_kyber::kyber768::{decapsulate, Ciphertext, SecretKey};
use hkdf::Hkdf;
use sha2::Sha256;

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
    if data.is_null() || ciphertext.is_null() || secret_key.is_null() || len == 0 {
        return 1;
    }

    unsafe {
        // 2. Conversión segura de bytes a tipos PQC
        let ct_bytes = std::slice::from_raw_parts(ciphertext, ct_len);
        let sk_bytes = std::slice::from_raw_parts(secret_key, sk_len);

        let ct = match Ciphertext::from_bytes(ct_bytes) {
            Ok(c) => c,
            Err(_) => return 2, // Error: Ciphertext inválido
        };
        
        let sk = match SecretKey::from_bytes(sk_bytes) {
            Ok(s) => s,
            Err(_) => return 3, // Error: SecretKey inválido
        };
        
        // Decapsulación (Kyber768 devuelve SharedSecret directamente)
        let ss = decapsulate(&ct, &sk);

        // 3. Derivación de clave industrial (HKDF-SHA256)
        let hk = Hkdf::<Sha256>::new(None, ss.as_bytes());
        let mut key_bytes = [0u8; 32];
        
        if hk.expand(b"VIVAR_INDUSTRIAL_PQC_KEY_2026", &mut key_bytes).is_err() {
            return 4;
        }
        
        let mut session_key = SessionKey(key_bytes);
        
        // 4. Difusión de estado (ARX)
        let data_slice = std::slice::from_raw_parts_mut(data, len);
        let mut state: u64 = 0x5A5A5A5A5A5A5A5A;
        
        for i in 0..len {
            let key_byte = session_key.0[i % 32];
            
            state = state.wrapping_add(data_slice[i] as u64).rotate_left(7);
            let mask = (state ^ (i as u64)).to_le_bytes()[0];
            
            data_slice[i] ^= key_byte ^ mask;
        }

        // 5. Limpieza absoluta
        session_key.zeroize();
        state.zeroize();
    }
    0
}
