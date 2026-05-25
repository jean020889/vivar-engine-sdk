#![crate_type = "cdylib"]

use std::slice;
use zeroize::Zeroize;
use hkdf::Hkdf;
use sha2::Sha256;

#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    data: *mut u8, 
    len: usize, 
    offset: usize, // Punto de inicio para evitar corromper el header
    key: *const u8, 
    key_len: usize
) -> i32 {
    // 1. Verificación de seguridad: prevenimos buffer overflows y punteros nulos
    if data.is_null() || key.is_null() || len == 0 || offset >= len { 
        return 1; 
    }
    
    unsafe {
        let data_slice = slice::from_raw_parts_mut(data, len);
        let key_slice = slice::from_raw_parts(key, key_len);
        
        // 2. Derivación de clave (HKDF-SHA256)
        let salt = b"VIVAR_ENGINE_PQC_SALT_2026";
        let hk = Hkdf::<Sha256>::new(Some(salt), key_slice);
        
        let mut okm = [0u8; 64];
        if hk.expand(b"VIVAR_ENGINE_STATE_EXPANSION", &mut okm).is_err() {
            return 2;
        }

        let mut state: [u64; 8] = [0; 8];
        for i in 0..8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&okm[i * 8..(i + 1) * 8]);
            state[i] = u64::from_le_bytes(buf);
        }
        okm.zeroize();

        // 3. Difusión de estado (Permutación ARX 12 rondas)
        for round in 0..12 {
            for i in 0..8 {
                state[i] ^= state[(i + 1) % 8].rotate_left(13);
                state[i] = state[i].wrapping_add(state[(i + 7) % 8].rotate_left(round as u32));
                state[i] ^= 0x9E3779B97F4A7C15u64.wrapping_mul(round as u64);
            }
        }

        // 4. Aplicación de máscara (Respetando el offset de integridad)
        // Solo mutamos desde el offset hasta el final, protegiendo el header
        for i in offset..len {
            let mask = (state[((i - offset) / 8) % 8] >> (((i - offset) % 8) * 8)) as u8;
            data_slice[i] ^= mask;
        }

        state.zeroize();
    }
    
    0 // Éxito
}
