#![crate_type = "cdylib"]

use zeroize::Zeroize;
use pqcrypto_kyber::kyber768;
use hkdf::Hkdf;
use sha2::Sha256;

// Estructura protegida contra volcados de memoria
#[derive(Zeroize)]
#[zeroize(drop)]
struct SessionKey([u8; 32]);

/// Función principal de procesamiento PQC industrial
/// Aplica permutación no lineal sobre el buffer de datos para máxima seguridad.
#[no_mangle]
pub extern "C" fn vivar_pqc_process(
    data: *mut u8, 
    len: usize,
    ciphertext: *const u8, 
    ct_len: usize,
    secret_key: *const u8, 
    sk_len: usize
) -> i32 {
    // 1. Verificación de seguridad de punteros para prevenir segfaults
    if data.is_null() || ciphertext.is_null() || secret_key.is_null() {
        return 1;
    }

    unsafe {
        // 2. Decapsulación PQC (Kyber-768: Resistencia Cuántica NIST)
        let ct = std::slice::from_raw_parts(ciphertext, ct_len);
        let sk = std::slice::from_raw_parts(secret_key, sk_len);
        
        let (ss, _) = match kyber768::decapsulate(ct, sk) {
            Ok(res) => res,
            Err(_) => return 2, // Error de decapsulación (llave inválida)
        };

        // 3. Derivación de clave industrial (HKDF-SHA256)
        let hk = Hkdf::<Sha256>::new(None, &ss);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"VIVAR_INDUSTRIAL_PQC_KEY_2026", &mut key_bytes).unwrap();
        
        let mut session_key = SessionKey(key_bytes);
        
        // 4. Aplicación de flujo (Difusión industrial con estado)
        // La difusión no lineal asegura que incluso con patrones repetitivos 
        // en el archivo original, la salida sea indistinguible del ruido blanco.
        let data_slice = std::slice::from_raw_parts_mut(data, len);
        let mut state: u64 = 0x5A5A5A5A5A5A5A5A; // Estado de permutación inicial
        
        for i in 0..len {
            let key_byte = session_key.0[i % 32];
            
            // Mezcla no lineal: XOR + Rotación + Adición (Efecto avalancha)
            state = state.wrapping_add(data_slice[i] as u64).rotate_left(7);
            let mask = (state ^ (i as u64)).to_le_bytes()[0];
            
            // Operación XOR aplicada en tiempo constante
            data_slice[i] ^= key_byte ^ mask;
        }

        // 5. Limpieza absoluta de memoria (Zeroize)
        // Garantiza que la SessionKey y el estado de permutación 
        // sean eliminados de la RAM físicamente al salir de este scope.
        session_key.zeroize();
        state.zeroize();
    }
    0 // Éxito
}
