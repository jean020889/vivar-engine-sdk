import os
import ctypes
import platform
import base64
import sys
from flask import Flask, render_template, request, send_file
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
ext = ".so"
lib_path = os.path.abspath(os.path.join(BASE_DIR, '..', 'target', 'release', f"libvivar_engine{ext}"))

try:
    lib = ctypes.CDLL(lib_path)
    lib.generate_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.seal_secret.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(PqcVault)]
    lib.vivar_pqc_process.argtypes = [
        ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, 
        ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, 
        ctypes.POINTER(ctypes.c_char), ctypes.c_size_t
    ]
except Exception as e:
    print(f"ERROR: No se cargó la librería: {e}")
    sys.exit(1)

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
    
    portador = request.files['file_portador']
    secreto = request.files['file_secreto']
    nombre_original = secure_filename(portador.filename)
    
    # 1. Leer datos
    data_portador = portador.read()
    blob_secreto = bytearray(secreto.read())
    
    # 2. Procesar con PQC
    with open(VAULT_PATH, "rb") as f: vault = PqcVault.from_buffer_copy(f.read())
    lib.vivar_pqc_process(
        (ctypes.c_char * len(blob_secreto)).from_buffer(blob_secreto), len(blob_secreto),
        vault.ciphertext, 1088,
        vault.encrypted_payload, 2400
    )
    
    # 3. Guardar sin prefijos corruptores
    ruta_temp = os.path.join(UPLOAD_FOLDER, nombre_original)
    with open(ruta_temp, "wb") as f: 
        f.write(data_portador + SEPARATOR + secreto.filename.encode() + META_SEPARATOR + base64.b64encode(blob_secreto))
    
    # 4. Enviar con nombre original usando download_name
    return send_file(ruta_temp, as_attachment=True, download_name=nombre_original)

@app.route("/extraer", methods=["POST"])
def extraer():
    archivo = request.files['file_cargado']
    data = archivo.read()
    
    if SEPARATOR not in data: return "Archivo inválido", 400
    
    partes = data.split(SEPARATOR, 1)
    meta_info, b64_secreto = partes[1].split(META_SEPARATOR, 1)
    
    secreto = bytearray(base64.b64decode(b64_secreto))
    
    with open(VAULT_PATH, "rb") as f: vault = PqcVault.from_buffer_copy(f.read())
    lib.vivar_pqc_process(
        (ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto),
        vault.ciphertext, 1088,
        vault.encrypted_payload, 2400
    )
    
    ruta_out = os.path.join(UPLOAD_FOLDER, secure_filename(meta_info.decode()))
    with open(ruta_out, "wb") as f: f.write(secreto)
    
    return send_file(ruta_out, as_attachment=True, download_name=meta_info.decode())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
