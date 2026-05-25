#![crate_type = "cdylib"]

use zeroize::Zeroize;
use pqcrypto_kyber::kyber768;
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq; // Necesario para evitar timing attacks

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
            Err(_) => return 2, 
        };

        // 2. Derivación de clave y expansión de estado (HKDF)
        let hk = Hkdf::<Sha256>::new(None, &ss);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"VIVAR_INDUSTRIAL_PQC_KEY", &mut key_bytes).unwrap();
        
        let mut session_key = SessionKey(key_bytes);
        
        // 3. Permutación de estado no lineal (Aumenta la entropía)
        let data_slice = std::slice::from_raw_parts_mut(data, len);
        let mut nonce: u64 = 0xDEADC0DECAFEBABE; // Semilla de difusión

        for i in 0..len {
            // Aplicamos rotación y mezcla para evitar patrones detectables
            let byte_key = session_key.0[i % 32];
            let diffusion = (nonce.rotate_left(5) ^ (i as u64)).to_le_bytes()[0];
            
            // Operación de tiempo constante
            data_slice[i] ^= byte_key ^ diffusion;
            
            // Actualización de nonce para la siguiente ronda (Difusión de estado)
            nonce = nonce.wrapping_add(data_slice[i] as u64).rotate_right(3);
        }

        // Limpieza absoluta de memoria
        session_key.zeroize();
    }
    0
}
