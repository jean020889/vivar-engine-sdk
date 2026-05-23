use pqcrypto_kyber::kyber512::{keypair, PublicKey, SecretKey};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};

#[no_mangle]
pub extern "C" fn generar_llaves_pqc() -> *mut (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    
    // Ahora que los traits están importados como 'as _', 
    // Rust sabe que existen los métodos as_bytes() para estas estructuras.
    let resultado = Box::new((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()));
    
    // Pasamos el puntero al heap para que Python pueda acceder a él
    Box::into_raw(resultado)
}

#[no_mangle]
pub extern "C" fn liberar_llaves(ptr: *mut (Vec<u8>, Vec<u8>)) {
    if ptr.is_null() { return; }
    unsafe { drop(Box::from_raw(ptr)); }
}
