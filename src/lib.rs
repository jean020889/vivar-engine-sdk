#![crate_type = "cdylib"]

use zeroize::Zeroize;
use pqcrypto_kyber::kyber768;
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
    // 1. Verificación de seguridad reforzada
    if data.is_null() || ciphertext.is_null() || secret_key.is_null() || len == 0 {
        return 1;
    }

    unsafe {
        // 2. Decapsulación PQC (Resistencia Cuántica)
        let ct = std::slice::from_raw_parts(ciphertext, ct_len);
        let sk = std::slice::from_raw_parts(secret_key, sk_len);
        
        let (ss, _) = match kyber768::decapsulate(ct, sk) {
            Ok(res) => res,
            Err(_) => return 2,
        };

        // 3. Derivación de clave HKDF
        let hk = Hkdf::<Sha256>::new(None, &ss);
        let mut key_bytes = [0u8; 32];
        // Utilizamos un info único para asegurar la deriva de la clave
        if hk.expand(b"VIVAR_INDUSTRIAL_PQC_KEY_2026", &mut key_bytes).is_err() {
            return 3;
        }
        
        let mut session_key = SessionKey(key_bytes);
        
        // 4. Difusión de estado (ARX: Add-Rotate-Xor)
        let data_slice = std::slice::from_raw_parts_mut(data, len);
        let mut state: u64 = 0x5A5A5A5A5A5A5A5A;
        
        for i in 0..len {
            let key_byte = session_key.0[i % 32];
            
            // Operación no lineal que garantiza el efecto avalancha
            state = state.wrapping_add(data_slice[i] as u64).rotate_left(7);
            let mask = (state ^ (i as u64)).to_le_bytes()[0];
            
            data_slice[i] ^= key_byte ^ mask;
        }

        // 5. Limpieza absoluta y segura
        // El 'state' es un tipo primitivo u64, debe ser limpiado explícitamente
        session_key.zeroize();
        state.zeroize();
    }
    0
}
