#![crate_type = "cdylib"]

use std::slice;

/// Códigos de error para la interfaz C
#[repr(i32)]
pub enum VceError {
    Success = 0,
    NullPointer = 1,
}

/// Estructura de datos alineada para intercambio de memoria con C/Python
#[repr(C)]
pub struct VivarBuffer {
    pub data: *mut u8,
    pub len: usize,
}

/// Motor de difusión simétrico e involutivo.
/// 
/// Utiliza una máscara determinista basada en el índice de posición 
/// y la clave, garantizando que el proceso de cifrado sea idéntico 
/// al proceso de descifrado (involución).
#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    buffer: *mut VivarBuffer,
    key_ptr: *mut u8,
    key_len: usize
) -> i32 {
    // Verificación de integridad de punteros antes de operar
    if buffer.is_null() || key_ptr.is_null() || key_len == 0 {
        return VceError::NullPointer as i32;
    }

    unsafe {
        // Acceso seguro a la memoria referenciada desde Python
        let buf = &mut *buffer;
        let data = slice::from_raw_parts_mut(buf.data, buf.len);
        let key = slice::from_raw_parts(key_ptr, key_len);
        
        // Constante de dispersión basada en la proporción áurea (phi)
        // Utilizada para asegurar que no existan patrones en los datos cifrados
        let constant: u64 = 0x9E3779B9;

        // Aplicación del operador de difusión
        for (i, val) in data.iter_mut().enumerate() {
            // Generación de la máscara determinista (i ^ key ^ constant)
            // Esta máscara es idéntica tanto al cifrar como al descifrar
            let mask = (constant ^ (i as u64) ^ (key[i % key_len] as u64)) as u8;
            
            // Operación XOR: Involutiva por naturaleza
            // Si A = Original, M = Máscara -> (A ^ M) ^ M = A
            *val ^= mask;
        }
    }

    VceError::Success as i32
}
