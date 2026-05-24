import tkinter as tk
from tkinter import messagebox, ttk
import sys
import os

# Asegurar que el path incluya la raíz para evitar errores de importación de módulos locales
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Intentar importar el motor Vivar Engine
try:
    # Ajusta estos nombres según las funciones exactas expuestas en tu 'vivar_engine.py' o 'wrapper.py'
    # Ejemplo estándar: desde vivar_engine importar las funciones principales
    from vivar_engine import encod_vivar, decod_vivar
    MOTOR_DISPONIBLE = True
except ImportError:
    MOTOR_DISPONIBLE = False

class VivarEngineGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔏 Vivar Engine SDK - Panel de Control y Pruebas")
        self.root.geometry("650x500")
        self.root.configure(bg="#f5f6fa")
        
        # Estilos básicos
        style = ttk.Style()
        style.theme_use("clam")
        
        # --- Encabezado Estado del SDK ---
        frame_status = tk.Frame(root, bg="#dcdde1", height=30)
        frame_status.pack(fill=tk.X)
        
        estado_txt = "🟢 Motor Vivar Engine Vinculado" if MOTOR_DISPONIBLE else "🔴 Error: No se pudo importar vivar_engine.py"
        estado_color = "#2ed573" if MOTOR_DISPONIBLE else "#ff4757"
        lbl_status = tk.Label(frame_status, text=estado_txt, fg=estado_color, bg="#dcdde1", font=("Arial", 9, "bold"))
        lbl_status.pack(side=tk.LEFT, padx=10, pady=5)

        # --- Área de Entrada (Plaintext / Ciphertext) ---
        tk.Label(root, text="Datos de Entrada (Texto plano o Cifrado):", bg="#f5f6fa", font=("Arial", 10, "bold"), fg="#2f3640").pack(anchor=tk.W, padx=20, pady=(10, 2))
        self.txt_input = tk.Text(root, height=6, width=72, wrap=tk.WORD, font=("Courier New", 10), bd=1, relief=tk.SOLID)
        self.txt_input.pack(padx=20, pady=5)

        # --- Panel de Parámetros (Para futuras variables como llaves o salts) ---
        frame_params = tk.LabelFrame(root, text=" Configuración de Cripto-Prueba ", bg="#f5f6fa", font=("Arial", 9, "bold"), fg="#718093")
        frame_params.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(frame_params, text="Nota: El motor procesará los datos usando la configuración base del SDK.", bg="#f5f6fa", fg="#7f8c8d", font=("Arial", 9, "italic")).pack(padx=10, pady=5)

        # --- Botonera de Acciones ---
        frame_botones = tk.Frame(root, bg="#f5f6fa")
        frame_botones.pack(pady=10)

        self.btn_cifrar = tk.Button(frame_botones, text="🔒 Cifrar Datos", command=self.ejecutar_cifrado, bg="#10ac84", fg="white", width=16, font=("Arial", 10, "bold"), relief=tk.FLAT, cursor="hand2")
        self.btn_cifrar.pack(side=tk.LEFT, padx=10)

        self.btn_descifrar = tk.Button(frame_botones, text="🔓 Descifrar Datos", command=self.ejecutar_descifrado, bg="#2e86de", fg="white", width=16, font=("Arial", 10, "bold"), relief=tk.FLAT, cursor="hand2")
        self.btn_descifrar.pack(side=tk.LEFT, padx=10)

        btn_limpiar = tk.Button(frame_botones, text="🧹 Limpiar", command=self.limpiar_campos, bg="#ee5253", fg="white", width=10, font=("Arial", 10), relief=tk.FLAT, cursor="hand2")
        btn_limpiar.pack(side=tk.LEFT, padx=10)

        # --- Área de Salida (Output) ---
        tk.Label(root, text="Resultado del Procesamiento (Output):", bg="#f5f6fa", font=("Arial", 10, "bold"), fg="#2f3640").pack(anchor=tk.W, padx=20, pady=(10, 2))
        self.txt_output = tk.Text(root, height=7, width=72, wrap=tk.WORD, font=("Courier New", 10), bg="#2f3640", fg="#f5f6fa", bd=0)
        self.txt_output.pack(padx=20, pady=5)

        if not MOTOR_DISPONIBLE:
            self.btn_cifrar.config(state=tk.DISABLED)
            self.btn_descifrar.config(state=tk.DISABLED)

    def ejecutar_cifrado(self):
        data = self.txt_input.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Campo Vacío", "Por favor introduce datos para cifrar.")
            return
        try:
            # Llamada al core de tu encriptador
            resultado = encod_vivar(data) 
            self.mostrar_resultado(resultado)
        except Exception as e:
            messagebox.showerror("Crypto Error", f"Fallo en la capa del Encriptador:\n{str(e)}")

    def ejecutar_descifrado(self):
        data = self.txt_input.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Campo Vacío", "Por favor introduce el payload cifrado.")
            return
        try:
            # Llamada al core de tu encriptador para reversar
            resultado = decod_vivar(data)
            self.mostrar_resultado(resultado)
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Fallo al descifrar el payload. Verifique la integridad o las llaves:\n{str(e)}")

    def mostrar_resultado(self, texto):
        self.txt_output.config(state=tk.NORMAL)
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert(tk.END, str(texto))

    def limpiar_campos(self):
        self.txt_input.delete("1.0", tk.END)
        self.txt_output.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = VivarEngineGUI(root)
    root.mainloop()
                                                                                       
