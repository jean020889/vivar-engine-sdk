use pqcrypto_kyber::kyber512::{keypair, PublicKey, SecretKey};

#[no_mangle]
pub extern "C" fn generar_llaves() {
    println!("Motor PQC: Generando llaves seguras...");
}
