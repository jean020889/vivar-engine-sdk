import os
import ctypes
import platform
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'temp_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

SEPARATOR = b"###VIVAR_PQC_DATA###"

# --- CONFIGURACIÓN MOTOR ---
ext = ".so" if platform.system() != "Windows" else ".dll"
lib_path = os.path.join(BASE_DIR, '..', 'target', 'release', f"libvivar_engine{ext}")
if not os.path.exists(lib_path): lib_path = os.path.join(BASE_DIR, f"libvivar_engine{ext}")

lib = ctypes.CDLL(lib_path)
lib.vivar_pqc_process.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]

# --- RUTA PRINCIPAL (GET y POST) ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html", step=1)
    
    # Manejo del POST inicial (Validación de clave)
    if request.form.get("action") == "validar_clave":
        return render_template("index.html", step=2, clave=request.form.get("clave"), operacion=request.form.get("operacion"))
    
    return "Acción no reconocida", 400

# --- RUTA DE OCULTAR ---
@app.route("/ocultar", methods=["POST"])
def ocultar():
    portador = request.files['file_portador'].read()
    secreto = bytearray(request.files['file_secreto'].read())
    
    secret_key = open("secret.bin", "rb").read()
    ciphertext = open("ciphertext.bin", "rb").read()
    
    lib.vivar_pqc_process((ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto), ciphertext, 1088, secret_key, 2400)
    
    archivo_final = portador + SEPARATOR + secreto
    ruta = os.path.join(UPLOAD_FOLDER, secure_filename(request.files['file_portador'].filename))
    with open(ruta, "wb") as f: f.write(archivo_final)
    return send_file(ruta, as_attachment=True)

# --- RUTA DE EXTRAER ---
@app.route("/extraer", methods=["POST"])
def extraer():
    archivo_cargado = request.files['file_cargado'].read()
    _, secreto_cifrado = archivo_cargado.split(SEPARATOR)
    secreto = bytearray(secreto_cifrado)
    
    secret_key = open("secret.bin", "rb").read()
    ciphertext = open("ciphertext.bin", "rb").read()
    
    lib.vivar_pqc_process((ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto), ciphertext, 1088, secret_key, 2400)
    
    ruta_out = os.path.join(UPLOAD_FOLDER, "secreto_recuperado")
    with open(ruta_out, "wb") as f: f.write(secreto)
    return send_file(ruta_out, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
