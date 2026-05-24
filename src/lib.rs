#![crate_type = "cdylib"]
use std::slice;

#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    data: *mut u8, 
    len: usize,
    key: *const u8, 
    key_len: usize
) -> i32 {
    if data.is_null() || key.is_null() { return 1; }
    
    unsafe {
        let data_slice = slice::from_raw_parts_mut(data, len);
        let key_slice = slice::from_raw_parts(key, key_len);
        
        // Estado inicial de entropía
        let mut state: u64 = 0x9E3779B97F4A7C15;
        
        for (i, val) in data_slice.iter_mut().enumerate() {
            let k_byte = key_slice[i % key_len] as u64;
            
            // 1. Mezcla de estado (Permutación)
            state = state.rotate_left(13)
                         .wrapping_add(k_byte ^ (i as u64));
            
            // 2. Generación de máscara (No lineal)
            let mask = (state ^ (state >> 33)).wrapping_mul(0xff51afd7ed558ccd) as u8;
            
            // 3. Aplicación y Realimentación del estado con el valor modificado
            // Al realimentar con *val, el cambio se propaga al siguiente byte.
            *val ^= mask;
            state = state.wrapping_add(*val as u64);
        }
    }
    0
}
