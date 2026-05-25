import os
import sys
import ctypes
from tkinter import messagebox, ttk
import tkinter as tk

# =====================================================================
# --- 1. GENERACIÓN AUTOMÁTICA DE ARCHIVOS Y COMPILACIÓN (Rust Core) ---
# =====================================================================

os.makedirs("src", exist_ok=True)

# Motor Rust con protección de encabezados (Offset)
with open("src/lib.rs", "w", encoding="utf-8") as f:
    f.write(r'''#![crate_type = "cdylib"]
use std::slice;
use zeroize::Zeroize;

#[no_mangle]
pub extern "C" fn vivar_operator_engine(data: *mut u8, len: usize, offset: usize, key: *const u8, key_len: usize) -> i32 {
    if data.is_null() || key.is_null() || offset >= len { return 1; }

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

        // XOR Selectivo desde el OFFSET
        for i in offset..len {
            let mask = (state[((i - offset) / 8) % 8] >> (((i - offset) % 8) * 8)) as u8;
            data_slice[i] ^= mask;
        }
        state.zeroize();
    }
    0
}''')

with open("Cargo.toml", "w", encoding="utf-8") as f:
    f.write('[package]\nname = "vivar-engine"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\ncrate-type = ["cdylib"]\n\n[dependencies]\nzeroize = "1.7"')

print("Compilando Vivar Engine Core (Tier 1)...")
os.system("cargo build --release")

# =====================================================================
# --- 2. CAPA DE ENLACE DEL SDK (VivarEngineSDK Actualizado) ----------
# =====================================================================

class VivarEngineSDK:
    def __init__(self, lib_path="./target/release/libvivar_engine.so"):
        if os.name == 'nt': lib_path = lib_path.replace(".so", ".dll")
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Motor no compilado en: {lib_path}")

        self._core = ctypes.CDLL(lib_path)
        self._core.vivar_operator_engine.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_size_t, 
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
        ]
        self._core.vivar_operator_engine.restype = ctypes.c_int32

    def process(self, data: bytes, key: bytes, offset: int = 0) -> bytes:
        pad_len = 64 - (len(data) % 64)
        padded = data + b'\x80' + b'\x00' * (pad_len - 1)
        buffer = bytearray(padded)
        c_data = (ctypes.c_uint8 * len(buffer)).from_buffer(buffer)
        c_key = (ctypes.c_uint8 * len(key))(*key)
        self._core.vivar_operator_engine(c_data, len(buffer), offset, c_key, len(key))
        return bytes(buffer)

    def decrypt(self, encrypted_data: bytes, key: bytes, offset: int = 0) -> bytes:
        buffer = bytearray(encrypted_data)
        c_data = (ctypes.c_uint8 * len(buffer)).from_buffer(buffer)
        c_key = (ctypes.c_uint8 * len(key))(*key)
        self._core.vivar_operator_engine(c_data, len(buffer), offset, c_key, len(key))
        raw = bytes(buffer)
        idx = raw.rfind(b'\x80')
        return raw[:idx] if idx != -1 else raw

try:
    sdk = VivarEngineSDK()
    SDK_DISPONIBLE = True
except Exception as e:
    SDK_DISPONIBLE = False
    ERROR_DETALLE = str(e)

# =====================================================================
# --- 3. PANEL DE CONTROL GRÁFICO (GUI) ------------------------------
# =====================================================================

class VivarSDKInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("🔏 Vivar Engine Tier 1 - SDK Industrial")
        self.root.geometry("700x600")
        
        # --- Campo Offset (Nuevo requisito industrial) ---
        tk.Label(root, text="Offset de Protección (Header Bytes):").pack()
        self.ent_offset = tk.Entry(root)
        self.ent_offset.insert(0, "0") # 0 para texto plano, 1024/2048 para archivos
        self.ent_offset.pack()
        
        # (El resto de la lógica de botones permanece igual)
        # Solo asegúrate de pasar el offset:
        # cifrado_raw = sdk.process(datos_bytes, clave_bytes, offset=int(self.ent_offset.get()))

    # --- Métodos de procesado actualizados ---
    def procesar_cifrado(self):
        try:
            offset = int(self.ent_offset.get())
            clave_bytes = self.ent_key.get().encode()
            datos_bytes = self.txt_input.get("1.0", tk.END).strip().encode()
            cifrado_raw = sdk.process(datos_bytes, clave_bytes, offset=offset)
            self.actualizar_output(cifrado_raw.hex())
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def procesar_descifrado(self):
        try:
            offset = int(self.ent_offset.get())
            clave_bytes = self.ent_key.get().encode()
            datos_cifrados = bytes.fromhex(self.txt_input.get("1.0", tk.END).strip())
            descifrado_bytes = sdk.decrypt(datos_cifrados, clave_bytes, offset=offset)
            self.actualizar_output(descifrado_bytes.decode(errors='ignore'))
        except Exception as e:
            messagebox.showerror("Error", str(e))

# ... (resto del mainloop igual)
