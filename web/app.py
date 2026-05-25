import os
import ctypes
import platform
from flask import Flask, render_template, request, send_file, make_response, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'temp_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

SECRET_PATH = os.path.join(BASE_DIR, "secret.bin")
CT_PATH = os.path.join(BASE_DIR, "ciphertext.bin")
SEPARATOR = b"###VIVAR_PQC_DATA###"
META_SEPARATOR = b"|||"

# --- CONFIGURACIÓN MOTOR ---
ext = ".so" if platform.system() != "Windows" else ".dll"
# Buscamos en la ruta absoluta correcta según tu estructura
lib_path = os.path.join(BASE_DIR, '..', 'target', 'release', f"libvivar_engine{ext}")
if not os.path.exists(lib_path): 
    lib_path = os.path.join(BASE_DIR, f"libvivar_engine{ext}")

lib = ctypes.CDLL(lib_path)

# Definición de tipos de datos para la interfaz C
lib.vivar_pqc_process.argtypes = [
    ctypes.POINTER(ctypes.c_char), 
    ctypes.c_size_t,               
    ctypes.POINTER(ctypes.c_char), 
    ctypes.c_size_t,               
    ctypes.POINTER(ctypes.c_char), 
    ctypes.c_size_t                
]

def init_crypto():
    pk = ctypes.create_string_buffer(1184)
    sk = ctypes.create_string_buffer(2400)
    ct = ctypes.create_string_buffer(1088)
    lib.generate_keys(pk, sk)
    lib.generate_ciphertext(pk, ct)
    with open(SECRET_PATH, "wb") as f: f.write(sk.raw)
    with open(CT_PATH, "wb") as f: f.write(ct.raw)

# --- RUTAS ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET": return render_template("index.html", step=1)
    if request.form.get("action") == "validar_clave":
        return render_template("index.html", step=2, clave=request.form.get("clave"), operacion=request.form.get("operacion"))
    return render_template("index.html", step=1)

@app.route("/ocultar", methods=["POST", "GET"])
def ocultar():
    if request.method == "GET": return redirect(url_for('index'))
    if not os.path.exists(SECRET_PATH): init_crypto()
    
    portador = request.files['file_portador'].read()
    file_secreto = request.files['file_secreto']
    nombre_archivo = file_secreto.filename.encode()
    secreto = bytearray(file_secreto.read())
    
    secret_key = open(SECRET_PATH, "rb").read()
    ciphertext = open(CT_PATH, "rb").read()
    
    # Llamada al motor con conversión a punteros c_char
    lib.vivar_pqc_process(
        (ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto),
        ctypes.c_char_p(ciphertext), 1088,
        ctypes.c_char_p(secret_key), 2400
    )
    
    payload = nombre_archivo + META_SEPARATOR + secreto
    filename_portador = secure_filename(request.files['file_portador'].filename)
    ruta = os.path.join(UPLOAD_FOLDER, filename_portador)
    with open(ruta, "wb") as f: f.write(portador + SEPARATOR + payload)
    
    return send_file(ruta, mimetype="application/octet-stream", as_attachment=True, download_name=filename_portador)

@app.route("/extraer", methods=["POST", "GET"])
def extraer():
    if request.method == "GET": return redirect(url_for('index'))
    if not os.path.exists(SECRET_PATH): init_crypto()
    
    archivo_cargado = request.files['file_cargado'].read()
    if SEPARATOR not in archivo_cargado: return "Archivo inválido", 400
    
    partes = archivo_cargado.split(SEPARATOR, 1)
    payload = partes[1]
    nombre_original, secreto_cifrado = payload.split(META_SEPARATOR, 1)
    secreto = bytearray(secreto_cifrado)
    
    secret_key = open(SECRET_PATH, "rb").read()
    ciphertext = open(CT_PATH, "rb").read()
    
    lib.vivar_pqc_process(
        (ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto),
        ctypes.c_char_p(ciphertext), 1088,
        ctypes.c_char_p(secret_key), 2400
    )
    
    ruta_out = os.path.join(UPLOAD_FOLDER, nombre_original.decode())
    with open(ruta_out, "wb") as f: f.write(secreto)
    
    return send_file(ruta_out, mimetype="application/octet-stream", as_attachment=True, download_name=nombre_original.decode())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
