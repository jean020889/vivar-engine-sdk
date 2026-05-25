import os
import sys
import ctypes
import platform
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'temp_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- FUNCIÓN DE BÚSQUEDA UNIVERSAL ---
def find_file(filename, start_dir):
    for root, dirs, files in os.walk(start_dir):
        if filename in files:
            return os.path.join(root, filename)
    return None

# --- 1. Detección Universal ---
ext = ".so" if platform.system() != "Windows" else ".dll"
lib_name = f"libvivar_engine{ext}"

# Escaneo automático
lib_path = find_file(lib_name, os.path.join(BASE_DIR, '..')) or find_file(lib_name, BASE_DIR)
key_path = find_file('keypair.bin', os.path.join(BASE_DIR, '..')) or find_file('keypair.bin', BASE_DIR)

if not lib_path:
    print(f"ERROR CRÍTICO: No se encontró {lib_name} en el sistema.")
    sys.exit(1)

lib = ctypes.CDLL(lib_path)
lib.vivar_pqc_process.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t
]
lib.vivar_pqc_process.restype = ctypes.c_int

# --- 2. Lógica de Negocio ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "validar_clave":
            clave = request.form.get("clave")
            operacion = request.form.get("operacion")
            if clave and len(clave) >= 4:
                return render_template("index.html", step=2, clave=clave, operacion=operacion)
            return render_template("index.html", step=1, error="Clave inválida.")

        if action == "ejecutar_stego":
            file_portador = request.files.get('file_portador')
            clave = request.form.get('clave', '')
            
            # Buscar el archivo si se movió o si la ruta cambió
            current_key_path = find_file('keypair.bin', BASE_DIR)
            
            if not current_key_path:
                return render_template("index.html", step=2, error="Error: keypair.bin no encontrado en ninguna carpeta.", clave=clave)

            try:
                with open(current_key_path, "rb") as f:
                    key_data = f.read()
                
                filename = secure_filename(file_portador.filename)
                portador_data = bytearray(file_portador.read())
                
                status = lib.vivar_pqc_process(
                    (ctypes.c_char * len(portador_data)).from_buffer(portador_data),
                    len(portador_data),
                    key_data, len(key_data),
                    key_data, len(key_data)
                )
                
                if status == 0:
                    ruta = os.path.join(UPLOAD_FOLDER, filename)
                    with open(ruta, "wb") as f:
                        f.write(portador_data)
                    return render_template("index.html", step=3, archivo_resultante=filename)
                else:
                    return render_template("index.html", step=2, error=f"Error PQC (Status: {status})", clave=clave)
            except Exception as e:
                return render_template("index.html", step=2, error=str(e), clave=clave)
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, secure_filename(filename)), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
