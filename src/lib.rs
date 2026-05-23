use zeroize::Zeroize;
use pqcrypto_kyber::kyber768::{encapsulate, keypair, PublicKey};
// Importación explícita de traits
use pqcrypto_traits::kem::PublicKey as PkTrait;
use pqcrypto_traits::kem::SecretKey as SkTrait;
use pqcrypto_traits::kem::Ciphertext as CtTrait;
use pqcrypto_traits::kem::SharedSecret as SsTrait;

#[repr(C)]
pub struct VivarBuffer {
    pub data: *mut u8,
    pub len: usize,
}

#[no_mangle]
#[allow(unused_mut)]
pub extern "C" fn vivar_operator_engine(
    buffer: *mut VivarBuffer,
    key_ptr: *mut u8,
    key_len: usize
) -> i32 {
    if buffer.is_null() || key_ptr.is_null() { return 1; }
    
    unsafe {
        let buf = &mut *buffer;
        let data_slice = std::slice::from_raw_parts_mut(buf.data, buf.len);
        let key_slice = std::slice::from_raw_parts_mut(key_ptr, key_len);
        
        for i in 0..buf.len {
            data_slice[i] ^= key_slice[i % key_len];
        }
        
        let mut key_mut = key_slice;
        key_mut.zeroize();
    }
    0
}

#[no_mangle]
pub extern "C" fn generate_pqc_keys(pk_out: *mut u8, sk_out: *mut u8) -> i32 {
    let (pk, sk) = keypair();
    unsafe {
        std::ptr::copy_nonoverlapping(PkTrait::as_bytes(&pk).as_ptr(), pk_out, 1184);
        std::ptr::copy_nonoverlapping(SkTrait::as_bytes(&sk).as_ptr(), sk_out, 2400);
    }
    0
}

#[no_mangle]
pub extern "C" fn perform_kem_encapsulation(
    pk_in: *const u8, 
    ct_out: *mut u8, 
    ss_out: *mut u8
) -> i32 {
    unsafe {
        let pk = match PublicKey::from_bytes(std::slice::from_raw_parts(pk_in, 1184)) {
            Ok(k) => k,
            Err(_) => return 2,
        };
        let (ct, ss) = encapsulate(&pk);
        
        // CORRECCIÓN AQUÍ: ct usa CtTrait y ss usa SsTrait
        std::ptr::copy_nonoverlapping(CtTrait::as_bytes(&ct).as_ptr(), ct_out, 1088);
        std::ptr::copy_nonoverlapping(SsTrait::as_bytes(&ss).as_ptr(), ss_out, 32);
    }
    0
}
