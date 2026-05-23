use pqcrypto_kyber::kyber512::{keypair, PublicKey, SecretKey};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _}; // Esto soluciona el error E0599

#[no_mangle]
pub extern "C" fn generar_llaves_pqc() -> *mut (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    // Ahora pk.as_bytes() funcionará porque el trait está en scope
    let resultado = Box::new((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()));
    Box::into_raw(resultado)
}

#[no_mangle]
pub extern "C" fn liberar_llaves(ptr: *mut (Vec<u8>, Vec<u8>)) {
    unsafe { Box::from_raw(ptr) };
}
