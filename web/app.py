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
    return render_template("index.html", step=1)

@app.route("/ocultar", methods=["POST"])
def ocultar():
    if not os.path.exists(VAULT_PATH): init_crypto()
    
    portador_file = request.files['file_portador']
    secreto_file = request.files['file_secreto']
    
    data_portador = portador_file.read()
    secreto = bytearray(secreto_file.read())
    
    # Cifrado
    with open(VAULT_PATH, "rb") as f: vault = PqcVault.from_buffer_copy(f.read())
    lib.vivar_pqc_process(
        (ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto),
        vault.ciphertext, 1088,
        vault.encrypted_payload, 2400
    )
    
    # Codificación Base64 para integridad binaria
    secreto_b64 = base64.b64encode(secreto)
    
    ruta = os.path.join(UPLOAD_FOLDER, "stego_" + secure_filename(portador_file.filename))
    with open(ruta, "wb") as f: 
        f.write(data_portador + SEPARATOR + secure_filename(secreto_file.filename).encode() + META_SEPARATOR + secreto_b64)
    
    response = make_response(send_file(ruta, as_attachment=True))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

@app.route("/extraer", methods=["POST"])
def extraer():
    archivo_cargado = request.files['file_cargado'].read()
    partes = archivo_cargado.split(SEPARATOR, 1)
    meta, secreto_b64 = partes[1].split(META_SEPARATOR, 1)
    
    # Decodificación Base64
    secreto = bytearray(base64.b64decode(secreto_b64))
    
    with open(VAULT_PATH, "rb") as f: vault = PqcVault.from_buffer_copy(f.read())
    lib.vivar_pqc_process(
        (ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto),
        vault.ciphertext, 1088,
        vault.encrypted_payload, 2400
    )
    
    ruta_out = os.path.join(UPLOAD_FOLDER, meta.decode())
    with open(ruta_out, "wb") as f: f.write(secreto)
    
    response = make_response(send_file(ruta_out, as_attachment=True))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
