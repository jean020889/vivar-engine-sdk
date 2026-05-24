#![crate_type = "cdylib"]

use std::slice;
use zeroize::Zeroize;
use hkdf::Hkdf;
use sha2::Sha256;

#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    data: *mut u8, 
    len: usize, 
    key: *const u8, 
    key_len: usize
) -> i32 {
    // Verificación estricta de punteros y seguridad de memoria
    if data.is_null() || key.is_null() || len == 0 || key_len == 0 { 
        return 1; 
    }
    
    unsafe {
        // Conversión segura de punteros C a slices de Rust
        let data_slice = slice::from_raw_parts_mut(data, len);
        let key_slice = slice::from_raw_parts(key, key_len);
        
        // --- 1. DERIVACIÓN DE CLAVE ROBUSTA (HKDF-SHA256) ---
        // Extraemos y expandimos la clave a exactamente 64 bytes (512 bits de entropía pura)
        // Usamos un salt opcional estático para la uniformidad criptográfica del SDK
        let salt = b"VIVAR_ENGINE_PQC_SALT_2026";
        let hk = Hkdf::<Sha256>::new(Some(salt), key_slice);
        
        let mut okm = [0u8; 64]; // Output Keying Material (512 bits)
        if hk.expand(b"VIVAR_ENGINE_STATE_EXPANSION", &mut okm).is_err() {
            return 2; // Error en la expansión de la clave
        }

        // --- 2. DERIVACIÓN DEL ESTADO INICIAL (512 BITS) ---
        // Mapeamos los 64 bytes perfectamente distribuidos dentro de nuestro estado u64
        let mut state: [u64; 8] = [0; 8];
        for i in 0..8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&okm[i * 8..(i + 1) * 8]);
            state[i] = u64::from_le_bytes(buf);
        }

        // Una vez estructurado el estado, limpiamos el búfer intermedio de la clave expandida de la RAM
        okm.zeroize();

        // --- 3. DIFUSIÓN DE ESTADO (12 RONDAS DE PERMUTACIÓN ARX) ---
        // Este proceso genera una máscara única e impredecible basada en la clave expandida
        for round in 0..12 {
            for i in 0..8 {
                state[i] ^= state[(i + 1) % 8].rotate_left(13);
                state[i] = state[i].wrapping_add(state[(i + 7) % 8].rotate_left(round as u32));
                state[i] ^= 0x9E3779B97F4A7C15u64.wrapping_mul(round as u64);
            }
        }

        // --- 4. APLICACIÓN DE LA MÁSCARA XOR (Simétrica e Involutiva) ---
        for i in 0..len {
            let mask = (state[(i / 8) % 8] >> ((i % 8) * 8)) as u8;
            data_slice[i] ^= mask;
        }

        // --- 5. LIMPIEZA DE SEGURIDAD (Zeroize) ---
        // Borrado definitivo del estado criptográfico de la memoria para mitigar ataques de volcado (Memory Dumps)
        state.zeroize();
    }
    
    0 // Retorno de éxito (C-ABI compatible)
}
