#![crate_type = "cdylib"]
use std::slice;

#[no_mangle]
pub extern "C" fn vivar_operator_engine(data: *mut u8, len: usize, key: *const u8, key_len: usize) -> i32 {
    // Verificación de punteros y seguridad de memoria
    if data.is_null() || key.is_null() { return 1; }
    
    unsafe {
        // Conversión de punteros C a slices de Rust
        let data_slice = slice::from_raw_parts_mut(data, len);
        let key_slice = slice::from_raw_parts(key, key_len);
        
        // 1. Derivación del estado inicial (8 x u64 = 512 bits de estado)
        // Se usa toda la clave proporcionada mediante módulo para llenar el estado
        let mut state: [u64; 8] = [0; 8];
        for i in 0..8 {
            let mut buf = [0u8; 8];
            for j in 0..8 { 
                buf[j] = key_slice[(i * 8 + j) % key_len]; 
            }
            state[i] = u64::from_le_bytes(buf);
        }

        // 2. Difusión de estado (12 rondas de permutación)
        // Este proceso genera una máscara única para la clave dada
        for round in 0..12 {
            for i in 0..8 {
                state[i] ^= state[(i + 1) % 8].rotate_left(13);
                state[i] = state[i].wrapping_add(state[(i + 7) % 8].rotate_left(round as u32));
                state[i] ^= 0x9E3779B97F4A7C15u64.wrapping_mul(round as u64);
            }
        }

        // 3. Aplicación de la máscara XOR (Simétrica e Involutiva)
        // La misma operación cifra y descifra
        for i in 0..len {
            let mask = (state[(i / 8) % 8] >> ((i % 8) * 8)) as u8;
            data_slice[i] ^= mask;
        }
    }
    0 // Retorno de éxito (C-ABI compatible)
}
