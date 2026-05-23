import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
import sys
import threading
from client import VivarSDK
from stegano_handler import SteganoHandler # Asegúrate de tener este módulo

class VivarGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Vivar Engine")
        self.sdk = VivarSDK()
        self.target_path = ""
        self.carrier_path = ""

        # UI simplificada para mantener el enfoque en la operatividad
        tk.Label(root, text="Clave de acceso:").pack()
        self.key_entry = tk.Entry(root, show="*", width=40)
        self.key_entry.pack()

        self.mode = tk.StringVar(value="Encrypt")
        tk.OptionMenu(root, self.mode, "Encrypt", "Decrypt").pack()

        tk.Button(root, text="Archivo a Procesar", command=self.load_target).pack()
        tk.Button(root, text="Archivo Portador", command=self.load_carrier).pack()
        
        self.btn_run = tk.Button(root, text="EJECUTAR", command=self.start_thread, bg="#2ecc71")
        self.btn_run.pack(pady=10)
        
        self.progress = ttk.Progressbar(root, length=300, mode='indeterminate')
        self.progress.pack(pady=10)

    def load_target(self): self.target_path = filedialog.askopenfilename()
    def load_carrier(self): self.carrier_path = filedialog.askopenfilename()

    def start_thread(self):
        # Ejecuta en hilo separado para no congelar la GUI
        threading.Thread(target=self.run_engine, daemon=True).start()

    def run_engine(self):
        if not self.target_path or self.carrier_path:
            self.progress.start()
            try:
                # 1. Leer datos y obtener secreto (usando tu lógica PQC del SDK)
                # ... lógica de mutación con sdk.mutar_datos ...
                
                # 2. Inyectar en portador manteniendo nombre original
                salida_nombre = os.path.basename(self.carrier_path)
                SteganoHandler.procesar(self.carrier_path, resultado_cifrado, salida_nombre)
                
                self.progress.stop()
                messagebox.showinfo("Proceso", f"Archivo {salida_nombre} generado.")
            except Exception:
                # Silenciamos errores internos como solicitaste
                messagebox.showerror("Error", "Error durante la ejecución.")
        else:
            messagebox.showwarning("Atención", "Seleccione los archivos correctamente.")

if __name__ == "__main__":
    root = tk.Tk()
    app = VivarGUI(root)
    root.mainloop()
