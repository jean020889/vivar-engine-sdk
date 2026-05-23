use pqcrypto_kyber::kyber512::{keypair};
use pqcrypto_traits::kem::{PublicKey, SecretKey};

#[no_mangle]
pub extern "C" fn generar_llaves_pqc() -> *mut (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    
    // Aquí convertimos explícitamente usando las definiciones del trait
    let pk_bytes = <pqcrypto_kyber::kyber512::PublicKey as pqcrypto_traits::kem::PublicKey>::as_bytes(&pk).to_vec();
    let sk_bytes = <pqcrypto_kyber::kyber512::SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(&sk).to_vec();
    
    let resultado = Box::new((pk_bytes, sk_bytes));
    Box::into_raw(resultado)
}

#[no_mangle]
pub extern "C" fn liberar_llaves(ptr: *mut (Vec<u8>, Vec<u8>)) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}
