use pqcrypto_kyber::kyber512::{keypair, PublicKey, SecretKey};

#[no_mangle]
pub extern "C" fn generar_llaves_pqc() -> *mut (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    // Empaquetamos en un Box para que la memoria persista fuera de Rust
    let resultado = Box::new((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()));
    Box::into_raw(resultado)
}

#[no_mangle]
pub extern "C" fn liberar_llaves(ptr: *mut (Vec<u8>, Vec<u8>)) {
    unsafe { Box::from_raw(ptr) };
}
