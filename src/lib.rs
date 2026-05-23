use pqcrypto_kyber::kyber512::{keypair, PublicKey, SecretKey};
use pqcrypto_traits::kem::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait};

#[no_mangle]
pub extern "C" fn generar_llaves_pqc() -> *mut (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    
    // La forma correcta de invocar el método de un trait en Rust
    // es usar el trait como espacio de nombres sobre la instancia.
    let pk_bytes = PublicKeyTrait::as_bytes(&pk).to_vec();
    let sk_bytes = SecretKeyTrait::as_bytes(&sk).to_vec();
    
    let resultado = Box::new((pk_bytes, sk_bytes));
    Box::into_raw(resultado)
}

#[no_mangle]
pub extern "C" fn liberar_llaves(ptr: *mut (Vec<u8>, Vec<u8>)) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}
