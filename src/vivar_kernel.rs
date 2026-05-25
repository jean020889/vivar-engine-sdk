use sha2::{Sha256, Digest};

// 1. Constante derivada de la rigidez espectral de tu Operador Vivar
const VIVAR_SPECTRAL_CONSTANT: [u8; 32] = [
    0x4A, 0x1B, 0x8C, 0x3D, 0x9E, 0x2F, 0x50, 0x61, 
    0x72, 0x83, 0x94, 0xA5, 0xB6, 0xC7, 0xD8, 0xE9,
    0xFA, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x5A, 0x6B,
    0x7C, 0x8D, 0x9E, 0xAF, 0xB0, 0xC1, 0xD2, 0xE3
];

// 2. Tu Sal secreta (Valor único de tu instancia/instalación)
const VIVAR_SECRET_SALT: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
];

pub fn derive_hardened_key(session_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    // Inyectamos la rigidez espectral (Operador Vivar)
    hasher.update(VIVAR_SPECTRAL_CONSTANT); 
    
    // Añadimos la capa de protección adicional (Sal secreta)
    hasher.update(VIVAR_SECRET_SALT);
    
    // Mezclamos con la clave base generada por Kyber
    hasher.update(session_key);
    
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

