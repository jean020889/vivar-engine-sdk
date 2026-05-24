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
        
        for (i, val) in data_slice.iter_mut().enumerate() {
            let k_byte = key_slice[i % key_len] as u64;
            
            // Operador Vivar-A: Estado basado en posición e índice (Determinista e Involutivo)
            // Usamos una función de mezcla que no depende del valor cifrado, 
            // permitiendo que el descifrado sea idéntico.
            let mut state: u64 = (i as u64).wrapping_add(k_byte);
            state = state.wrapping_mul(0xbf58476d1ce4e5b9);
            state ^= state >> 30;
            state = state.wrapping_mul(0x94d049bb133111eb);
            state ^= state >> 27;
            state = state.wrapping_mul(0xbf58476d1ce4e5b9);
            
            let mask = (state & 0xFF) as u8;
            *val ^= mask;
        }
    }
    0
}
