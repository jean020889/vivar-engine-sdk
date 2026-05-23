import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
import sys

# Ajuste de ruta para importar el cliente
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from client import VivarSDK

class VivarGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Vivar Encryption Engine")
        self.sdk = VivarSDK()
        
        # Variables de estado
        self.target_path = ""
        self.carrier_path = ""

        # Layout
        tk.Label(root, text="Clave de acceso:").pack(pady=5)
        self.key_entry = tk.Entry(root, show="*", width=40)
        self.key_entry.pack()

        self.mode = tk.StringVar(value="Encrypt")
        tk.OptionMenu(root, self.mode, "Encrypt", "Decrypt").pack(pady=5)

        tk.Button(root, text="Subir archivo a procesar", command=self.load_target).pack()
        tk.Button(root, text="Seleccionar archivo portador", command=self.load_carrier).pack()
        
        tk.Button(root, text="EJECUTAR", command=self.run_engine, bg="#2ecc71", fg="white").pack(pady=10)
        
        self.progress = ttk.Progressbar(root, length=300, mode='determinate')
        self.progress.pack(pady=10)

    def load_target(self):
        self.target_path = filedialog.askopenfilename()

    def load_carrier(self):
        self.carrier_path = filedialog.askopenfilename()

    def run_engine(self):
        if not self.target_path or not self.carrier_path:
            messagebox.showerror("Error", "Seleccione ambos archivos.")
            return

        self.progress['value'] = 20
        # Simulación de proceso interno (Cifrado + Inyección esteganográfica)
        # Aquí llamarías a tu lógica de mutación:
        # resultado = self.sdk.mutar_datos(data, key)
        
        self.progress['value'] = 100
        messagebox.showinfo("Proceso", "Archivo procesado con éxito.")
        # Aquí habilitarías el botón de descarga para guardar con el mismo nombre del portador

if __name__ == "__main__":
    root = tk.Tk()
    app = VivarGUI(root)
    root.mainloop()
