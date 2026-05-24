#![crate_type = "cdylib"]

use std::slice;
use zeroize::Zeroize;

#[repr(i32)]
pub enum VceError {
    Success = 0,
    NullPointer = 1,
}

#[repr(C)]
pub struct VivarBuffer {
    pub data: *mut u8,
    pub len: usize,
}

// Operador de difusión simétrico e involutivo
fn vivar_diffusion_operator(data: &mut [u8], key: &[u8]) {
    let key_len = key.len();
    let constant: u64 = 0x9E3779B9;

    for (i, val) in data.iter_mut().enumerate() {
        let key_byte = key[i % key_len] as u64;
        let index = i as u64;
        
        // Transformación simétrica: no depende de estados previos (feedback)
        // Esto permite que cifrado == descifrado
        let transformation = (constant ^ index ^ key_byte).rotate_left(7);
        
        *val ^= (transformation & 0xFF) as u8;
    }
}

#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    buffer: *mut VivarBuffer,
    key_ptr: *mut u8,
    key_len: usize
) -> i32 {
    if buffer.is_null() || key_ptr.is_null() { return VceError::NullPointer as i32; }
    
    unsafe {
        let buf = &mut *buffer;
        let data_slice = slice::from_raw_parts_mut(buf.data, buf.len);
        let key_slice = slice::from_raw_parts(key_ptr, key_len);
        
        // La misma función realiza cifrado y descifrado
        vivar_diffusion_operator(data_slice, key_slice);
        
        // Limpiamos la clave de memoria
        let mut mut_key = slice::from_raw_parts_mut(key_ptr, key_len);
        mut_key.zeroize();
    }
    VceError::Success as i32
}
