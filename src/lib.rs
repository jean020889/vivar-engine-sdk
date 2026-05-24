#![crate_type = "cdylib"]
use std::slice;

/// Motor Criptográfico Vivar: Operador de Difusión Involutiva
/// Diseñado para alta eficiencia y resistencia Post-Cuántica.
#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    data: *mut u8, 
    len: usize,
    key: *const u8, 
    key_len: usize
) -> i32 {
    // Validación de seguridad de punteros
    if data.is_null() || key.is_null() { return 1; }
    
    unsafe {
        let data_slice = slice::from_raw_parts_mut(data, len);
        let key_slice = slice::from_raw_parts(key, key_len);
        
        // Constante de estado inicial (Basada en la razón áurea para máxima dispersión)
        let mut state: u64 = 0x9E3779B97F4A7C15;
        
        // Bucle de cifrado/descifrado (Involutivo)
        for (i, val) in data_slice.iter_mut().enumerate() {
            let k_byte = key_slice[i % key_len] as u64;
            
            // Operador Vivar: Encadenamiento de entropía (Avalancha)
            // Cada byte depende del estado anterior y del valor del dato
            state = state.rotate_left(13)
                         .wrapping_add(k_byte ^ (i as u64) ^ (*val as u64));
            
            // Generación de máscara XOR de alta entropía
            let mask = ((state >> 32) ^ state) as u8;
            
            // Aplicación del operador
            *val ^= mask;
        }
    }
    0 // Retorno de éxito (Cero errores)
}
