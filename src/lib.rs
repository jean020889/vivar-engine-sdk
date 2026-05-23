use pqcrypto_kyber::kyber512::{keypair, PublicKey, SecretKey};
use pqcrypto_traits::kem::PublicKey as KyberPublicKey;
use pqcrypto_traits::kem::SecretKey as KyberSecretKey;

#[no_mangle]
pub extern "C" fn generar_llaves_pqc() -> *mut (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    
    // Aquí invocamos el método de forma absoluta desde el trait importado
    let pk_bytes = KyberPublicKey::as_bytes(&pk).to_vec();
    let sk_bytes = KyberSecretKey::as_bytes(&sk).to_vec();
    
    let resultado = Box::new((pk_bytes, sk_bytes));
    Box::into_raw(resultado)
}

#[no_mangle]
pub extern "C" fn liberar_llaves(ptr: *mut (Vec<u8>, Vec<u8>)) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}
