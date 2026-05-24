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
        
        let mut state: u64 = 0x9E3779B97F4A7C15;
        
        for (i, val) in data_slice.iter_mut().enumerate() {
            let k_byte = key_slice[i % key_len] as u64;
            
            // Incrementamos la complejidad: mezclamos el índice, la llave y el valor
            state = state.rotate_left(13)
                         .wrapping_add(k_byte)
                         .wrapping_add(i as u64)
                         .wrapping_add(*val as u64);
            
            // Aplicamos una transformación no lineal al estado para generar la máscara
            let mask = ((state ^ (state >> 33)).wrapping_mul(0xff51afd7ed558ccd)) as u8;
            
            // Cifrado y encadenamiento: el valor cifrado actual modifica el estado del siguiente
            *val ^= mask;
            state = state.wrapping_add(*val as u64); 
        }
    }
    0
}
