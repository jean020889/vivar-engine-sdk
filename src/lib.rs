use pqcrypto_kyber::kyber512::{keypair};

#[no_mangle]
pub extern "C" fn generar_llaves_pqc() -> *mut (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    
    // Convertimos directamente a Vec<u8> sin invocar métodos de traits conflictivos
    let pk_vec = pk.to_bytes().to_vec();
    let sk_vec = sk.to_bytes().to_vec();
    
    let resultado = Box::new((pk_vec, sk_vec));
    Box::into_raw(resultado)
}

#[no_mangle]
pub extern "C" fn liberar_llaves(ptr: *mut (Vec<u8>, Vec<u8>)) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}
