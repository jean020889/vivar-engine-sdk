#![crate_type = "cdylib"]
use std::slice;

#[repr(i32)]
pub enum VceError { Success = 0, NullPointer = 1 }

#[repr(C)]
pub struct VivarBuffer { pub data: *mut u8, pub len: usize }

#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    buffer: *mut VivarBuffer,
    key_ptr: *mut u8,
    key_len: usize
) -> i32 {
    if buffer.is_null() || key_ptr.is_null() || key_len == 0 { return VceError::NullPointer as i32; }
    
    unsafe {
        let buf = &mut *buffer;
        let data = slice::from_raw_parts_mut(buf.data, buf.len);
        let key = slice::from_raw_parts(key_ptr, key_len);
        
        let constant: u64 = 0x9E3779B9;

        for (i, val) in data.iter_mut().enumerate() {
            // Generamos una máscara basada en la posición y la llave
            // Esta máscara es idéntica en el cifrado y en el descifrado
            let mask = (constant ^ (i as u64) ^ (key[i % key_len] as u64)) as u8;
            
            // Operación XOR involutiva pura: (A ^ M) ^ M = A
            *val ^= mask;
        }
    }
    VceError::Success as i32
}
