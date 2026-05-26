import os
import ctypes
import platform
import base64
from flask import Flask, render_template, request, send_file, make_response
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'temp_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

VAULT_PATH = os.path.join(BASE_DIR, "secret.vault")
SEPARATOR = b"###VIVAR_PQC_DATA###"
META_SEPARATOR = b"|||"

class PqcVault(ctypes.Structure):
    _fields_ = [("ciphertext", ctypes.c_char * 1088),
                ("encrypted_payload", ctypes.c_char * 2400)]

# Carga de librería
ext = ".so" if platform.system() != "Windows" else ".dll"
lib_path = os.path.join(BASE_DIR, '..', 'target', 'release', f"libvivar_engine{ext}")
if not os.path.exists(lib_path): lib_path = os.path.join(BASE_DIR, f"libvivar_engine{ext}")

lib = ctypes.CDLL(lib_path)
lib.generate_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.seal_secret.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(PqcVault)]
lib.vivar_pqc_process.argtypes = [
    ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, 
    ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, 
    ctypes.POINTER(ctypes.c_char), ctypes.c_size_t
]

def init_crypto():
    pk = ctypes.create_string_buffer(1184)
    sk = ctypes.create_string_buffer(2400)
    vault = PqcVault()
    lib.generate_keys(pk, sk)
    lib.seal_secret(pk, sk, ctypes.byref(vault))
    with open(VAULT_PATH, "wb") as f: f.write(bytes(vault))

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        return render_template("index.html", step=2, clave=request.form.get("clave"), operacion=request.form.get("operacion"))
    return render_template("index.html", step=1)

@app.route("/ocultar", methods=["POST"])
def ocultar():
    if not os.path.exists(VAULT_PATH): init_crypto()
    
    portador_file = request.files['file_portador']
    secreto_file = request.files['file_secreto']
    
    # Lectura segura
    data_portador = portador_file.read()
    secreto = bytearray(secreto_file.read())
    
    with open(VAULT_PATH, "rb") as f: vault = PqcVault.from_buffer_copy(f.read())
    
    lib.vivar_pqc_process(
        (ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto),
        vault.ciphertext, 1088,
        vault.encrypted_payload, 2400
    )
    
    secreto_b64 = base64.b64encode(secreto)
    
    # Escritura por bloques para evitar corrupción
    ruta = os.path.join(UPLOAD_FOLDER, "stego_" + secure_filename(portador_file.filename))
    with open(ruta, "wb") as f: 
        f.write(data_portador)
        f.write(SEPARATOR)
        f.write(secure_filename(secreto_file.filename).encode())
        f.write(META_SEPARATOR)
        f.write(secreto_b64)
    
    response = make_response(send_file(ruta, as_attachment=True))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

@app.route("/extraer", methods=["POST"])
def extraer():
    archivo_cargado = request.files['file_cargado'].read()
    # Buscamos el separador de forma segura
    if SEPARATOR not in archivo_cargado: return "Error: Archivo no contiene datos protegidos", 400
    
    partes = archivo_cargado.split(SEPARATOR, 1)
    meta_info, secreto_b64 = partes[1].split(META_SEPARATOR, 1)
    
    secreto = bytearray(base64.b64decode(secreto_b64))
    
    with open(VAULT_PATH, "rb") as f: vault = PqcVault.from_buffer_copy(f.read())
    
    lib.vivar_pqc_process(
        (ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto),
        vault.ciphertext, 1088,
        vault.encrypted_payload, 2400
    )
    
    ruta_out = os.path.join(UPLOAD_FOLDER, meta_info.decode())
    with open(ruta_out, "wb") as f: f.write(secreto)
    
    response = make_response(send_file(ruta_out, as_attachment=True))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response
