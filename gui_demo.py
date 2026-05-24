                    import tkinter as tk
from tkinter import messagebox, ttk
import sys
import os

# Asegurar que el script reconozca módulos locales si es necesario
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Intentar importar e inicializar el SDK de Vivar
try:
    from vivar_sdk import VivarEngineSDK
    
    # Intentamos buscar la librería según el sistema operativo (Linux/macOS .so, Windows .dll)
    # Por defecto tu SDK usa "./target/release/libvivar_engine.so"
    lib_path = "./target/release/libvivar_engine.so"
    if os.name == 'nt': # Windows
        lib_path = "./target/release/vivar_engine.dll"
        
    sdk = VivarEngineSDK(lib_path=lib_path)
    SDK_DISPONIBLE = True
except Exception as e:
    SDK_DISPONIBLE = False
    ERROR_DETALLE = str(e)

class VivarSDKInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("🔑 Vivar Engine - Panel Gráfico de Pruebas SDK")
        self.root.geometry("700x550")
        self.root.configure(bg="#f4f6f9")
        
        # --- Barra de Estado ---
        frame_status = tk.Frame(root, bg="#dfe4ea", height=30)
        frame_status.pack(fill=tk.X, side=tk.TOP)
        
        if SDK_DISPONIBLE:
            estado_txt = "🟢 SDK Inicializado y Vinculado con éxito (Rust Core activo)"
            estado_color = "#2ed573"
        else:
            estado_txt = f"🔴 Error de Carga del SDK: Asegúrate de compilar con Cargo. {ERROR_DETALLE[:50]}..."
            estado_color = "#ff4757"
            
        lbl_status = tk.Label(frame_status, text=estado_txt, fg=estado_color, bg="#dfe4ea", font=("Arial", 9, "bold"))
        lbl_status.pack(side=tk.LEFT, padx=10, pady=5)

        # --- Contenedor Principal ---
        main_container = tk.Frame(root, bg="#f4f6f9")
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # --- Entrada de la Clave/Key ---
        tk.Label(main_container, text="Clave de Cifrado (Secret Key):", bg="#f4f6f9", font=("Arial", 10, "bold"), fg="#2f3542").pack(anchor=tk.W, pady=(5, 2))
        self.ent_key = tk.Entry(main_container, font=("Courier New", 11), bd=1, relief=tk.SOLID)
        self.ent_key.insert(0, "VIVAR_ENGINE_PROD_2026_SECURITY_32")  # Llave por defecto de tu test
        self.ent_key.pack(fill=tk.X, pady=5)

        # --- Entrada de Datos ---
        tk.Label(main_container, text="Datos de Entrada (Texto plano o Cifrado Hexadecimal):", bg="#f4f6f9", font=("Arial", 10, "bold"), fg="#2f3542").pack(anchor=tk.W, pady=(10, 2))
        self.txt_input = tk.Text(main_container, height=6, wrap=tk.WORD, font=("Courier New", 10), bd=1, relief=tk.SOLID)
        self.txt_input.insert(tk.END, "Resolucion BSD rank 33") # Texto de ejemplo
        self.txt_input.pack(fill=tk.X, pady=5)

        # --- Botones de Control ---
        frame_botones = tk.Frame(main_container, bg="#f4f6f9")
        frame_botones.pack(pady=15)

        self.btn_cifrar = tk.Button(frame_botones, text="🔒 Cifrar", command=self.procesar_cifrado, bg="#2ed573", fg="white", width=15, font=("Arial", 10, "bold"), relief=tk.FLAT, cursor="hand2")
        self.btn_cifrar.pack(side=tk.LEFT, padx=10)

        self.btn_descifrar = tk.Button(frame_botones, text="🔓 Descifrar", command=self.procesar_descifrado, bg="#1e90ff", fg="white", width=15, font=("Arial", 10, "bold"), relief=tk.FLAT, cursor="hand2")
        self.btn_descifrar.pack(side=tk.LEFT, padx=10)

        btn_limpiar = tk.Button(frame_botones, text="🧹 Limpiar", command=self.limpiar_campos, bg="#ff4757", fg="white", width=10, font=("Arial", 10), relief=tk.FLAT, cursor="hand2")
        btn_limpiar.pack(side=tk.LEFT, padx=10)

        # --- Salida de Resultados ---
        tk.Label(main_container, text="Resultado (Output en Hex / Texto):", bg="#f4f6f9", font=("Arial", 10, "bold"), fg="#2f3542").pack(anchor=tk.W, pady=(10, 2))
        self.txt_output = tk.Text(main_container, height=7, wrap=tk.WORD, font=("Courier New", 10), bg="#2f3542", fg="#ffffff", bd=0)
        self.txt_output.pack(fill=tk.X, pady=5)

        # Desactivar botones si el SDK no cargó correctamente
        if not SDK_DISPONIBLE:
            self.btn_cifrar.config(state=tk.DISABLED)
            self.btn_descifrar.config(state=tk.DISABLED)
            messagebox.showerror("Error de Entorno", f"No se pudo cargar el SDK.\nDetalle: {ERROR_DETALLE}\n\nAsegúrate de ejecutar 'cargo build --release' antes de lanzar la GUI.")

    def procesar_cifrado(self):
        key_str = self.ent_key.get().strip()
        data_str = self.txt_input.get("1.0", tk.END).strip()

        if not key_str or not data_str:
            messagebox.showwarning("Campos vacíos", "La clave y los datos de entrada son obligatorios.")
            return

        try:
            # Conversión a bytes para el SDK
            clave_bytes = key_str.encode('utf-8')
            datos_bytes = data_str.encode('utf-8')

            # Ejecución del cifrado en el núcleo de Rust
            cifrado_raw = sdk.process(datos_bytes, clave_bytes)
            
            # Como el output es binario cifrado, lo mostramos en formato Hexadecimal legible
            hex_output = cifrado_raw.hex()
            
            self.actualizar_output(hex_output)
        except Exception as e:
            messagebox.showerror("Error de Cifrado", f"Ocurrió un error en el motor:\n{str(e)}")

    def procesar_descifrado(self):
        key_str = self.ent_key.get().strip()
        data_str = self.txt_input.get("1.0", tk.END).strip()

        if not key_str or not data_str:
            messagebox.showwarning("Campos vacíos", "La clave y los datos de entrada son obligatorios.")
            return

        try:
            clave_bytes = key_str.encode('utf-8')
            
            # El texto de entrada para descifrar debe venir en formato Hexadecimal (el entregado por el cifrador)
            try:
                datos_cifrados_bytes = bytes.fromhex(data_str)
            except ValueError:
                messagebox.showerror("Error de Formato", "Para descifrar, la entrada debe ser una cadena Hexadecimal válida (sin espacios ni caracteres extra).")
                return

            # Ejecución del descifrado en el núcleo de Rust y remoción automática de padding
            descifrado_bytes = sdk.decrypt(datos_cifrados_bytes, clave_bytes)
            
            # Intentamos decodificar a UTF-8 legible
            try:
                resultado_final = descifrado_bytes.decode('utf-8')
            except UnicodeDecodeError:
                resultado_final = f"[Binario Raw]: {str(descifrado_bytes)}"

            self.actualizar_output(resultado_final)
        except Exception as e:
            messagebox.showerror("Error de Descifrado", f"Error al procesar descifrado:\n{str(e)}")

    def actualizar_output(self, texto):
        self.txt_output.config(state=tk.NORMAL)
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert(tk.END, texto)

    def limpiar_campos(self):
        self.txt_input.delete("1.0", tk.END)
        self.txt_output.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = VivarSDKInterface(root)
    root.mainloop()
                                                                   
