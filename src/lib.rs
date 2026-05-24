#![crate_type = "cdylib"]
use std::slice;

#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    data: *mut u8, 
    len: usize,
    key: *const u8, 
    key_len: usize
) -> i32 {
    if data.is_null() || key.is_null() || len == 0 { return 1; }
    
    unsafe {
        let data_slice = slice::from_raw_parts_mut(data, len);
        let key_slice = slice::from_raw_parts(key, key_len);
        
        // Constantes de dispersión de alta entropía
        let mut state: u64 = 0x9E3779B97F4A7C15; 
        
        for (i, val) in data_slice.iter_mut().enumerate() {
            // Mezcla de estado: El "poder" del cifrador radica en esta rotación
            let k_byte = key_slice[i % key_len] as u64;
            state = state.rotate_left(13).wrapping_add(k_byte ^ (i as u64));
            
            // Transformación no lineal para máxima difusión
            let mask = ((state >> 32) ^ state) as u8;
            *val ^= mask;
        }
    }
    0
}
