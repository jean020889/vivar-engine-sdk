import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import hashlib
import os

# Importación de tus módulos personalizados
from vivar_sdk import VivarEngineSDK
from stegano_handler import SteganoHandler

class VivarEngineApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vivar Engine SDK - Secure Suite")
        self.root.geometry("450x550")
        
        self.sdk = VivarEngineSDK()
        self.key = tk.StringVar()
        self.archivo_fuente = None
        self.archivo_portador = None
        
        # --- UI Layout ---
        tk.Label(root, text="Vivar Encryption Suite", font=('Arial', 14, 'bold')).pack(pady=10)
        
        tk.Label(root, text="Clave Maestra:", font=('Arial', 10)).pack(pady=5)
        self.entry_key = tk.Entry(root, textvariable=self.key, show="*", width=40)
        self.entry_key.pack()
        
        self.mode = tk.StringVar(value="Cifrar")
        tk.Radiobutton(root, text="Cifrar y Ocultar", variable=self.mode, value="Cifrar").pack()
        tk.Radiobutton(root, text="Extraer y Descifrar", variable=self.mode, value="Descifrar").pack()
        
        self.btn_action = tk.Button(root, text="Iniciar Proceso", command=self.preparar_proceso, bg="#2c3e50", fg="white", width=20)
        self.btn_action.pack(pady=20)
        
        self.progress = ttk.Progressbar(root, length=300, mode='determinate')
        self.progress.pack(pady=10)
        
        self.status = tk.Label(root, text="Estado: Esperando usuario", font=('Arial', 8, 'italic'))
        self.status.pack()

    def calcular_hash(self, ruta_archivo):
        sha256 = hashlib.sha256()
        with open(ruta_archivo, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    def preparar_proceso(self):
        if not self.key.get():
            return messagebox.showerror("Error", "La clave maestra es obligatoria.")
        
        self.archivo_fuente = filedialog.askopenfilename(title="Seleccionar archivo a cifrar/descifrar")
        if not self.archivo_fuente: return
        
        self.archivo_portador = filedialog.askopenfilename(title="Seleccionar portador")
        if not self.archivo_portador: return
        
        self.btn_action.config(state=tk.DISABLED)
        threading.Thread(target=self._proceso_logico, daemon=True).start()

    def _proceso_logico(self):
        try:
            self.progress['value'] = 10
            self.status.config(text="Calculando integridad y procesando...")
            
            # --- Lógica de cifrado/descifrado ---
            if self.mode.get() == "Cifrar":
                hash_orig = self.calcular_hash(self.archivo_fuente)
                with open(self.archivo_fuente, 'rb') as f: data = f.read()
                
                self.progress['value'] = 30
                cifrados = self.sdk.execute_mutation(data, self.key.get(), encrypt=True)
                
                self.progress['value'] = 70
                SteganoHandler.ocultar_en_portador(cifrados, self.archivo_portador, self.archivo_portador)
                
            else: # Descifrar
                datos_ocultos = SteganoHandler.extraer_de_portador(self.archivo_portador)
                resultado = self.sdk.execute_mutation(datos_ocultos, self.key.get(), encrypt=False)
                
                with open("archivo_recuperado.dat", "wb") as f:
                    f.write(resultado)
            
            self.progress['value'] = 100
            self.status.config(text="Proceso finalizado con éxito.")
            messagebox.showinfo("Éxito", "Operación completada correctamente.")
            
        except Exception as e:
            messagebox.showerror("Error del Motor", f"Detalles: {str(e)}")
        finally:
            self.reiniciar()

    def reiniciar(self):
        self.key.set("")
        self.progress['value'] = 0
        self.btn_action.config(state=tk.NORMAL)
        self.status.config(text="Estado: Esperando usuario")

if __name__ == "__main__":
    root = tk.Tk()
    app = VivarEngineApp(root)
    root.mainloop()
