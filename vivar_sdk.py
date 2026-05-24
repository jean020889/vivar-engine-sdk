import os
import ctypes
from tabulate import tabulate

# --- 1. GENERACIÓN DE ARCHIVOS (Rust) ---
os.makedirs("src", exist_ok=True)
with open("src/lib.rs", "w") as f:
    f.write(r'''#![crate_type = "cdylib"]
use std::slice;
#[no_mangle]
pub extern "C" fn vivar_operator_engine(data: *mut u8, len: usize, key: *const u8, key_len: usize) -> i32 {
    if data.is_null() || key.is_null() { return 1; }
    unsafe {
        let data_slice = slice::from_raw_parts_mut(data, len);
        let key_slice = slice::from_raw_parts(key, key_len);
        let mut state: [u64; 8] = [0; 8];
        for i in 0..8 {
            let mut buf = [0u8; 8];
            for j in 0..8 { buf[j] = key_slice[(i * 8 + j) % key_len]; }
            state[i] = u64::from_le_bytes(buf);
        }
        for round in 0..12 {
            for i in 0..8 {
                state[i] ^= state[(i + 1) % 8].rotate_left(13);
                state[i] = state[i].wrapping_add(state[(i + 7) % 8].rotate_left(round as u32));
                state[i] ^= 0x9E3779B97F4A7C15u64.wrapping_mul(round as u64);
            }
        }
        for i in 0..len {
            let mask = (state[(i / 8) % 8] >> ((i % 8) * 8)) as u8;
            data_slice[i] ^= mask;
        }
    }
    0
}''')

with open("Cargo.toml", "w") as f:
    f.write('[package]\nname = "vivar-engine"\nversion = "0.1.0"\nedition = "2021"\n[lib]\ncrate-type = ["cdylib"]')

# Recompilación
!cargo build --release

# --- 2. SDK DEFINITIVO (Python) ---
class VivarEngineSDK:
    def __init__(self, lib_path="./target/release/libvivar_engine.so"):
        self._core = ctypes.CDLL(lib_path)
        self._core.vivar_operator_engine.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

    def process(self, data: bytes, key: bytes) -> bytes:
        pad_len = 64 - (len(data) % 64)
        padded = data + b'\x80' + b'\x00' * (pad_len - 1)
        buffer = bytearray(padded)
        c_data = (ctypes.c_uint8 * len(buffer)).from_buffer(buffer)
        c_key = (ctypes.c_uint8 * len(key))(*key)
        self._core.vivar_operator_engine(c_data, len(buffer), c_key, len(key))
        return bytes(buffer)

    def decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        buffer = bytearray(encrypted_data)
        c_data = (ctypes.c_uint8 * len(buffer)).from_buffer(buffer)
        c_key = (ctypes.c_uint8 * len(key))(*key)
        self._core.vivar_operator_engine(c_data, len(buffer), c_key, len(key))
        raw = bytes(buffer)
        return raw.split(b'\x80', 1)[0] if b'\x80' in raw else raw

# --- 3. VALIDACIÓN FINAL ---
sdk = VivarEngineSDK()
clave = b"VIVAR_ENGINE_PROD_2026_SECURITY_32"
casos = [
    {"desc": "Texto Corto", "data": b"Hola"},
    {"desc": "BSD Conjetura", "data": b"Resolucion BSD rank 33"},
    {"desc": "Binarios", "data": b"\x00\xff\x20\x40\x80"},
    {"desc": "Largo (>64 bytes)", "data": b"Validacion industrial 2026 con exito total del sistema vivar."}
]

resultados = []
for caso in casos:
    cifrado = sdk.process(caso["data"], clave)
    recuperado = sdk.decrypt(cifrado, clave)
    resultados.append([caso["desc"], len(caso["data"]), "✅ PASÓ" if caso["data"] == recuperado else "❌ FALLÓ"])

print(tabulate(resultados, headers=["Caso de Prueba", "Bytes", "Estado"], tablefmt="grid"))
