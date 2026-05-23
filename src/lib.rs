#![crate_type = "cdylib"]

use std::slice;
use zeroize::Zeroize;

#[repr(C)]
pub struct VivarBuffer {
    pub data: *mut u8,
    pub len: usize,
}

/// Motor de Cifrado Vivar (VCE) - Versión Final
/// Utiliza encadenamiento CBC para asegurar la difusión de datos.
/// is_encrypt: 1 para Cifrar, 0 para Descifrar.
#[no_mangle]
pub extern "C" fn vivar_crypt_engine(
    buffer: *mut VivarBuffer,
    key_ptr: *mut u8,
    key_len: usize,
    is_encrypt: u8 
) -> i32 {
    if buffer.is_null() || key_ptr.is_null() { return 1; }
    
    unsafe {
        let buf = &mut *buffer;
        let data_slice = slice::from_raw_parts_mut(buf.data, buf.len);
        let key_slice = slice::from_raw_parts_mut(key_ptr, key_len);
        
        let mut feedback: u8 = 0;
        let encrypt = is_encrypt != 0;
        
        for i in 0..buf.len {
            let nonce = (i & 0xFF) as u8;
            let val = data_slice[i];
            
            if encrypt {
                let current = val ^ key_slice[i % key_len] ^ nonce ^ feedback;
                data_slice[i] = current;
                feedback = current;
            } else {
                let decrypted = val ^ feedback ^ nonce ^ key_slice[i % key_len];
                data_slice[i] = decrypted;
                feedback = val;
            }
        }
        key_slice.zeroize();
    }
    0
}
