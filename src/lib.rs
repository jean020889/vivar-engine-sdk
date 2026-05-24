# 1. Reescribir el archivo lib.rs para eliminar el texto que causó el error
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
        
        let mut state: u64 = 0x9E3779B97F4A7C15;
        
        for (i, val) in data_slice.iter_mut().enumerate() {
            let k_byte = key_slice[i % key_len] as u64;
            
            // Difusión encadenada: el estado depende del valor previo del dato
            state = state.rotate_left(13)
                         .wrapping_add(k_byte ^ (i as u64) ^ (*val as u64));
            
            let mask = ((state >> 32) ^ state) as u8;
            *val ^= mask;
        }
    }
    0
}
""")

# 2. Asegurar que el entorno de Rust esté activo
import os
os.environ["PATH"] += os.pathsep + os.path.expanduser("~/.cargo/bin")

# 3. Compilar nuevamente
!cargo build --release
