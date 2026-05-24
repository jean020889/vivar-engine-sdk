# Actualizamos el núcleo en src/lib.rs para encadenar el estado
with open("src/lib.rs", "w") as f:
    f.write("""#![crate_type = "cdylib"]
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
            
            // DIFUSIÓN ENCADENADA: El estado depende del valor previo del dato
            state = state.rotate_left(13)
                         .wrapping_add(k_byte ^ (i as u64) ^ (*val as u64));
            
            let mask = ((state >> 32) ^ state) as u8;
            *val ^= mask;
        }
    }
    0
}
""")

# Re-compilar el núcleo con la nueva lógica
!cargo build --release
