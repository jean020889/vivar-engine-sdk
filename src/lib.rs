use pqcrypto_kyber::kyber512::{keypair, PublicKey, SecretKey};
use pqcrypto_traits::kem::PublicKey as _;
use pqcrypto_traits::kem::SecretKey as _;

#[no_mangle]
pub extern "C" fn generar_llaves_pqc() -> *mut (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    
    // Convertimos a bytes usando los traits importados
    let pk_vec = <PublicKey as pqcrypto_traits::kem::PublicKey>::as_bytes(&pk).to_vec();
    let sk_vec = <SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(&sk).to_vec();
    
    let resultado = Box::new((pk_vec, sk_vec));
    Box::into_raw(resultado)
}

#[no_mangle]
pub extern "C" fn liberar_llaves(ptr: *mut (Vec<u8>, Vec<u8>)) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}
