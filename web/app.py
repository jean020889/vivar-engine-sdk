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

# --- 1. CONFIGURACIÓN DEL MOTOR ---
ext = ".so" if platform.system() != "Windows" else ".dll"
lib_name = f"libvivar_engine{ext}"
lib_path = os.path.join(BASE_DIR, '..', 'target', 'release', lib_name)
if not os.path.exists(lib_path): lib_path = os.path.join(BASE_DIR, lib_name)

if not os.path.exists(lib_path):
    print(f"ERROR: Librería {lib_name} no encontrada.")
    sys.exit(1)

lib = ctypes.CDLL(lib_path)
lib.generate_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.generate_ciphertext.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.generate_ciphertext.restype = ctypes.c_int
lib.vivar_pqc_process.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
lib.vivar_pqc_process.restype = ctypes.c_int

# --- 2. INICIALIZACIÓN DE CLAVES REALES ---
def init_crypto():
    pk = ctypes.create_string_buffer(1184)
    sk = ctypes.create_string_buffer(2400)
    ct = ctypes.create_string_buffer(1088)
    
    lib.generate_keys(pk, sk)
    with open("secret.bin", "wb") as f: f.write(sk.raw)
    
    lib.generate_ciphertext(pk, ct)
    with open("ciphertext.bin", "wb") as f: f.write(ct.raw)

if not os.path.exists("secret.bin") or not os.path.exists("ciphertext.bin"):
    init_crypto()

# --- 3. LÓGICA DE NEGOCIO ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "validar_clave":
            return render_template("index.html", step=2, clave=request.form.get("clave"))

        if action == "ejecutar_stego":
            file_portador = request.files.get('file_portador')
            
            try:
                secret_key = open("secret.bin", "rb").read()
                ciphertext = open("ciphertext.bin", "rb").read()
                portador_data = bytearray(file_portador.read())
                
                status = lib.vivar_pqc_process(
                    (ctypes.c_char * len(portador_data)).from_buffer(portador_data),
                    len(portador_data),
                    ciphertext, 1088,
                    secret_key, 2400
                )
                
                if status == 0:
                    ruta = os.path.join(UPLOAD_FOLDER, secure_filename(file_portador.filename))
                    with open(ruta, "wb") as f: f.write(portador_data)
                    return render_template("index.html", step=3, archivo_resultante=file_portador.filename)
                else:
                    return render_template("index.html", step=2, error=f"Error PQC (Status: {status})")
            except Exception as e:
                return render_template("index.html", step=2, error=str(e))
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, secure_filename(filename)), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
