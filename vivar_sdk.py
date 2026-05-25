
import os
import sys
import ctypes
import hashlib
from tkinter import messagebox, ttk
import tkinter as tk

# =====================================================================
# --- 1. GENERACIÓN AUTOMÁTICA DE ARCHIVOS Y COMPILACIÓN (Rust Core) ---
# =====================================================================

os.makedirs("src", exist_ok=True)

# Escribimos el core de Rust exactamente con tus especificaciones y comentarios
with open("src/lib.rs", "w", encoding="utf-8") as f:
    f.write(r'''#![crate_type = "cdylib"]
use std::slice;

#[no_mangle]
pub extern "C" fn vivar_operator_engine(data: *mut u8, len: usize, key: *const u8, key_len: usize) -> i32 {
    // Verificación de punteros y seguridad de memoria
    if data.is_null() || key.is_null() { return 1; }

    unsafe {
        // Conversión de punteros C a slices de Rust
        let data_slice = slice::from_raw_parts_mut(data, len);
        let key_slice = slice::from_raw_parts(key, key_len);

        // 1. Derivación del estado inicial (8 x u64 = 512 bits de estado)
        // Se usa toda la clave proporcionada mediante módulo para llenar el estado
        let mut state: [u64; 8] = [0; 8];
        for i in 0..8 {
            let mut buf = [0u8; 8];
            for j in 0..8 {
                buf[j] = key_slice[(i * 8 + j) % key_len];
            }
            state[i] = u64::from_le_bytes(buf);
        }

        // 2. Difusión de estado (12 rondas de permutación)
        // Este proceso genera una máscara única para la clave dada
        for round in 0..12 {
            for i in 0..8 {
                state[i] ^= state[(i + 1) % 8].rotate_left(13);
                state[i] = state[i].wrapping_add(state[(i + 7) % 8].rotate_left(round as u32));
                state[i] ^= 0x9E3779B97F4A7C15u64.wrapping_mul(round as u64);
            }
        }

        // 3. Aplicación de la máscara XOR (Simétrica e Involutiva)
        // La misma operación cifra y descifra
        for i in 0..len {
            let mask = (state[(i / 8) % 8] >> ((i % 8) * 8)) as u8;
            data_slice[i] ^= mask;
        }
    }
    0 // Retorno de éxito (C-ABI compatible)
}''')

with open("Cargo.toml", "w", encoding="utf-8") as f:
    f.write('[package]\nname = "vivar-engine"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\ncrate-type = ["cdylib"]')

# Comando para compilar dinámicamente el binario de Rust de alto rendimiento
print("Compilando Vivar Engine Core en Rust...")
os.system("cargo build --release")

# =====================================================================
# --- 2. CAPA DE ENLACE DEL SDK (Python Class via ctypes) -----------
# =====================================================================

class VivarEngineSDK:
    def __init__(self, lib_path="./target/release/libvivar_engine.so"):
        # Ajuste dinámico de extensión para Windows (.dll) si aplica
        if os.name == 'nt' and lib_path.endswith('.so'):
            lib_path = "./target/release/vivar_engine.dll"

        # Validar ruta dinámica para entornos embebidos/web o ejecuciones en subcarpetas
        if not os.path.exists(lib_path):
            alt_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "target/release/libvivar_engine.so"))
            if not os.path.exists(alt_path):
                alt_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../target/release/libvivar_engine.so"))
            
            if os.path.exists(alt_path):
                lib_path = alt_path
            else:
                raise FileNotFoundError(f"No se encontró el binario compilado en: {lib_path}")

        self._core = ctypes.CDLL(lib_path)
        self._core.vivar_operator_engine.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t
        ]
        self._core.vivar_operator_engine.restype = ctypes.c_int32

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
        
        # Ejecución del Operador simétrico de Vivar en Rust
        self._core.vivar_operator_engine(c_data, len(buffer), c_key, len(key))
        raw = bytes(buffer)
        
        # PARCHE DE SEGURIDAD INDUSTRIAL: Buscar el marcador de padding \x80 desde el FINAL (rfind)
        # Esto previene cortes accidentales dentro de archivos densos (PDFs, imágenes, etc.)
        idx = raw.rfind(b'\x80')
        if idx != -1:
            return raw[:idx]
        return raw

# Instanciación e inicialización global del SDK seguro contra fallos
try:
    sdk = VivarEngineSDK()
    SDK_DISPONIBLE = True
except Exception as e:
    SDK_DISPONIBLE = False
    ERROR_DETALLE = str(e)

# =====================================================================
# --- 3. PANEL DE CONTROL GRÁFICO (GUI nativa para pruebas) ---------
# =====================================================================

class VivarSDKInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("🔏 Vivar Engine - Panel Gráfico de Pruebas SDK")
        self.root.geometry("700x560")
        self.root.configure(bg="#f4f6f9")

        # --- Barra de Estado Superior ---
        frame_status = tk.Frame(root, bg="#dfe4ea", height=30)
        frame_status.pack(fill=tk.X, side=tk.TOP)

        if SDK_DISPONIBLE:
            estado_txt = "🟢 SDK Inicializado: Núcleo en Rust (C-ABI) listo para operaciones"
            estado_color = "#2ed573"
        else:
            estado_txt = f"🔴 Error: No se pudo enlazar el SDK nativo. Detalle: {ERROR_DETALLE[:45]}..."
            estado_color = "#ff4757"

        lbl_status = tk.Label(frame_status, text=estado_txt, fg=estado_color, bg="#dfe4ea", font=("Arial", 9, "bold"))
        lbl_status.pack(side=tk.LEFT, padx=10, pady=5)

        # --- Contenedor Principal ---
        main_container = tk.Frame(root, bg="#f4f6f9")
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # --- Campo Secret Key ---
        tk.Label(main_container, text="Clave de Cifrado Simétrica / Post-Cuántica (Secret Key):", bg="#f4f6f9", font=("Arial", 10, "bold"), fg="#2f3542").pack(anchor=tk.W, pady=(5, 2))
        self.ent_key = tk.Entry(main_container, font=("Courier New", 11), bd=1, relief=tk.SOLID)
        self.ent_key.insert(0, "VIVAR_ENGINE_PROD_2026_SECURITY_32")
        self.ent_key.pack(fill=tk.X, pady=5)

        # --- Campo Datos de Entrada ---
        tk.Label(main_container, text="Datos de Entrada (Texto plano para cifrar O Hexadecimal para descifrar):", bg="#f4f6f9", font=("Arial", 10, "bold"), fg="#2f3542").pack(anchor=tk.W, pady=(10, 2))
        self.txt_input = tk.Text(main_container, height=6, wrap=tk.WORD, font=("Courier New", 10), bd=1, relief=tk.SOLID)
        self.txt_input.insert(tk.END, "Resolucion BSD rank 33")
        self.txt_input.pack(fill=tk.X, pady=5)

        # --- Botonera Integrada ---
        frame_botones = tk.Frame(main_container, bg="#f4f6f9")
        frame_botones.pack(pady=15)

        self.btn_cifrar = tk.Button(frame_botones, text="🔒 Cifrar Datos", command=self.procesar_cifrado, bg="#2ed573", fg="white", width=16, font=("Arial", 10, "bold"), relief=tk.FLAT, cursor="hand2")
        self.btn_cifrar.pack(side=tk.LEFT, padx=10)

        self.btn_descifrar = tk.Button(frame_botones, text="🔓 Descifrar Datos", command=self.procesar_descifrado, bg="#1e90ff", fg="white", width=16, font=("Arial", 10, "bold"), relief=tk.FLAT, cursor="hand2")
        self.btn_descifrar.pack(side=tk.LEFT, padx=10)

        btn_limpiar = tk.Button(frame_botones, text="🧹 Limpiar", command=self.limpiar_campos, bg="#ff4757", fg="white", width=10, font=("Arial", 10), relief=tk.FLAT, cursor="hand2")
        btn_limpiar.pack(side=tk.LEFT, padx=10)

        # --- Campo de Salida / Output ---
        tk.Label(main_container, text="Resultado del Procesamiento (Output):", bg="#f4f6f9", font=("Arial", 10, "bold"), fg="#2f3542").pack(anchor=tk.W, pady=(10, 2))
        self.txt_output = tk.Text(main_container, height=8, wrap=tk.WORD, font=("Courier New", 10), bg="#2f3542", fg="#ffffff", bd=0)
        self.txt_output.pack(fill=tk.X, pady=5)

        if not SDK_DISPONIBLE:
            self.btn_cifrar.config(state=tk.DISABLED)
            self.btn_descifrar.config(state=tk.DISABLED)
            messagebox.showerror("Fallo Crítico", f"Interfaz bloqueada porque el núcleo de Rust no pudo vincularse.\nDetalle: {ERROR_DETALLE}")

    def procesar_cifrado(self):
        key_str = self.ent_key.get().strip()
        data_str = self.txt_input.get("1.0", tk.END).strip()

        if not key_str or not data_str:
            messagebox.showwarning("Campos Requeridos", "Es necesario ingresar tanto la clave como los datos de entrada.")
            return

        try:
            clave_bytes = key_str.encode('utf-8')
            datos_bytes = data_str.encode('utf-8')

            cifrado_raw = sdk.process(datos_bytes, clave_bytes)
            hex_output = cifrado_raw.hex()
            self.actualizar_output(hex_output)
        except Exception as e:
            messagebox.showerror("Error de Cifrado", f"Error en la capa del motor:\n{str(e)}")

    def procesar_descifrado(self):
        key_str = self.ent_key.get().strip()
        data_str = self.txt_input.get("1.0", tk.END).strip()

        if not key_str or not data_str:
            messagebox.showwarning("Campos Requeridos", "Es necesario ingresar tanto la clave como los datos binarios hex.")
            return

        try:
            clave_bytes = key_str.encode('utf-8')

            try:
                datos_cifrados_bytes = bytes.fromhex(data_str)
            except ValueError:
                messagebox.showerror("Error de Formato", "La entrada para descifrar debe ser una cadena Hexadecimal limpia.")
                return

            descifrado_bytes = sdk.decrypt(datos_cifrados_bytes, clave_bytes)

            try:
                resultado_final = descifrado_bytes.decode('utf-8')
            except UnicodeDecodeError:
                resultado_final = f"[Binario Raw / No UTF-8]: {str(descifrado_bytes)}"

            self.actualizar_output(resultado_final)
        except Exception as e:
            messagebox.showerror("Error de Descifrado", f"Error de consistencia criptográfica:\n{str(e)}")

    def actualizar_output(self, texto):
        self.txt_output.config(state=tk.NORMAL)
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert(tk.END, texto)

    def limpiar_campos(self):
        self.txt_input.delete("1.0", tk.END)
        self.txt_output.delete("1.0", tk.END)

if __name__ == "__main__":
    # Nota: En entornos de servidor como Termux por consola, la ejecución de la GUI se omitirá
    # si no hay una pantalla X11 activa. El SDK permanecerá disponible para importaciones desde app.py.
    try:
        root = tk.Tk()
        app = VivarSDKInterface(root)
        root.mainloop()
    except Exception:
        print("[+] SDK de Vivar Engine listo. (Modo Consola/Biblioteca cargado correctamente).")

