// Importamos el keypair, pero NO los structs que colisionan con los traits
use pqcrypto_kyber::kyber512::keypair;
// Importamos los traits con nombres distintos para evitar colisiones
use pqcrypto_traits::kem::PublicKey as PublicKeyTrait;
use pqcrypto_traits::kem::SecretKey as SecretKeyTrait;

#[no_mangle]
pub extern "C" fn generar_llaves_pqc() -> *mut (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    
    // Ahora, al usar el alias del trait, el compilador sabe exactamente dónde buscar as_bytes()
    let pk_bytes = pk.as_bytes().to_vec();
    let sk_bytes = sk.as_bytes().to_vec();
    
    let resultado = Box::new((pk_bytes, sk_bytes));
    Box::into_raw(resultado)
}

#[no_mangle]
pub extern "C" fn liberar_llaves(ptr: *mut (Vec<u8>, Vec<u8>)) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}
