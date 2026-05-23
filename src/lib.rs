use pqcrypto_kyber::kyber512::{keypair};
use pqcrypto_traits::kem::{PublicKey, SecretKey};

#[no_mangle]
pub extern "C" fn generar_llaves_pqc() -> *mut (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    
    // Accedemos a los bytes convirtiendo directamente el struct 
    // usando la implementación del trait que ya está vinculada al tipo.
    let pk_vec = pk.as_bytes().to_vec();
    let sk_vec = sk.as_bytes().to_vec();
    
    let resultado = Box::new((pk_vec, sk_vec));
    Box::into_raw(resultado)
}

#[no_mangle]
pub extern "C" fn liberar_llaves(ptr: *mut (Vec<u8>, Vec<u8>)) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}
