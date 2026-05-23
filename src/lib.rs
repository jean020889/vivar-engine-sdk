use zeroize::Zeroize;
use pqcrypto_kyber::kyber768::{
    encapsulate, generate_keypair, PublicKey, SecretKey, Ciphertext, SharedSecret
};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _};

#[repr(C)]
pub struct VivarBuffer {
    pub data: *mut u8,
    pub len: usize,
}

/// Motor de mutación PQC: Procesa datos con una clave secreta y limpia memoria post-operación
#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    buffer: *mut VivarBuffer,
    key_ptr: *mut u8,
    key_len: usize
) -> i32 {
    if buffer.is_null() || key_ptr.is_null() { return 1; }

    unsafe {
        let buf = &mut *buffer;
        let data_slice = std::slice::from_raw_parts_mut(buf.data, buf.len);
        let mut key_slice = std::slice::from_raw_parts_mut(key_ptr, key_len);

        // --- LÓGICA VIVAR (Inserte aquí su algoritmo de mutación original) ---
        // Ejemplo simple: data[i] ^= key[i % key_len]
        for i in 0..buf.len {
            data_slice[i] ^= key_slice[i % key_len];
        }
        // ---------------------------------------------------------------------

        // ZEROIZE: Borrado crítico del material criptográfico en RAM
        key_slice.zeroize();
    }
    0
}

/// Genera par de claves PQC Kyber768. 
/// pk_out debe ser un buffer de 1184 bytes.
/// sk_out debe ser un buffer de 2400 bytes.
#[no_mangle]
pub extern "C" fn generate_pqc_keys(pk_out: *mut u8, sk_out: *mut u8) -> i32 {
    let (pk, sk) = generate_keypair();
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_bytes().as_ptr(), pk_out, 1184);
        std::ptr::copy_nonoverlapping(sk.as_bytes().as_ptr(), sk_out, 2400);
    }
    0
}

/// Encapsulación PQC: Genera el secreto compartido usando Kyber768.
/// pk_in: Buffer de 1184 bytes.
/// ct_out: Buffer de 1088 bytes.
/// ss_out: Buffer de 32 bytes.
#[no_mangle]
pub extern "C" fn perform_kem_encapsulation(
    pk_in: *const u8, 
    ct_out: *mut u8, 
    ss_out: *mut u8
) -> i32 {
    unsafe {
        let pk_slice = std::slice::from_raw_parts(pk_in, 1184);
        let pk = match PublicKey::from_bytes(pk_slice) {
            Ok(key) => key,
            Err(_) => return 2,
        };

        let (ct, ss) = encapsulate(&pk);
        
        std::ptr::copy_nonoverlapping(ct.as_bytes().as_ptr(), ct_out, 1088);
        std::ptr::copy_nonoverlapping(ss.as_bytes().as_ptr(), ss_out, 32);
    }
    0
}
