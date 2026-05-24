import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from vivar_sdk import VivarEngineSDK
from stegano_handler import SteganoHandler
import threading

class VivarEngineApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vivar Engine SDK - Secure Suite")
        self.root.geometry("450x500")
        
        self.sdk = VivarEngineSDK()
        self.key = tk.StringVar()
        self.archivo_cifrar = None
        self.archivo_portador = None
        
        # --- UI Layout ---
        tk.Label(root, text="Clave Maestra:", font=('Arial', 10, 'bold')).pack(pady=10)
        self.entry_key = tk.Entry(root, textvariable=self.key, show="*", width=40)
        self.entry_key.pack()
        
        self.mode = tk.StringVar(value="Cifrar")
        tk.Radiobutton(root, text="Cifrar y Ocultar", variable=self.mode, value="Cifrar").pack()
        tk.Radiobutton(root, text="Extraer y Descifrar", variable=self.mode, value="Descifrar").pack()
        
        self.btn_action = tk.Button(root, text="Seleccionar Archivo Fuente", command=self.paso1)
        self.btn_action.pack(pady=20)
        
        self.progress = ttk.Progressbar(root, length=300, mode='determinate')
        self.progress.pack(pady=10)
        
        self.status = tk.Label(root, text="Esperando instrucciones...")
        self.status.pack()

    def paso1(self):
        if not self.key.get():
            return messagebox.showerror("Error", "Clave requerida.")
        
        self.archivo_cifrar = filedialog.askopenfilename(title="Seleccionar archivo")
        if self.archivo_cifrar:
            self.archivo_portador = filedialog.askopenfilename(title="Seleccionar archivo portador")
            if self.archivo_portador:
                self.ejecutar_proceso()

    def ejecutar_proceso(self):
        # Ejecutamos en hilo separado para no congelar la GUI durante el cifrado/streaming
        threading.Thread(target=self._proceso_logico).start()

    def _proceso_logico(self):
        try:
            self.progress['value'] = 20
            self.status.config(text="Procesando motor criptográfico...")
            
            with open(self.archivo_cifrar, 'rb') as f:
                datos = f.read()
            
            # Cifrado
            cifrados = self.sdk.execute_mutation(datos, self.key.get(), encrypt=(self.mode.get()=="Cifrar"))
            self.progress['value'] = 60
            
            # Ocultamiento (Streaming)
            self.status.config(text="Integrando en portador...")
            SteganoHandler.ocultar_en_portador(cifrados, self.archivo_portador, self.archivo_portador)
            
            self.progress['value'] = 100
            self.status.config(text="Operación exitosa.")
            messagebox.showinfo("Éxito", "Proceso completado. El archivo portador está actualizado.")
            self.reiniciar()
            
        except Exception as e:
            messagebox.showerror("Error Crítico", str(e))
            self.reiniciar()

    def reiniciar(self):
        self.key.set("")
        self.progress['value'] = 0
        self.status.config(text="Esperando instrucciones...")

if __name__ == "__main__":
    root = tk.Tk()
    app = VivarEngineApp(root)
    root.mainloop()
