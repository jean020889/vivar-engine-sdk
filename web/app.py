import os
import ctypes
import platform
from flask import Flask, render_template, request, send_file, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'temp_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

VAULT_PATH = os.path.join(BASE_DIR, "secret.vault")
CT_PATH = os.path.join(BASE_DIR, "ciphertext.bin")
SEPARATOR = b"###VIVAR_PQC_DATA###"
META_SEPARATOR = b"|||"

# Definición alineada con Rust
class PqcVault(ctypes.Structure):
    _fields_ = [("ciphertext", ctypes.c_char * 1088),
                ("encrypted_payload", ctypes.c_char * 2400)]

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
    ct = ctypes.create_string_buffer(1088)
    
    lib.generate_keys(pk, sk)
    
    vault = PqcVault()
    lib.seal_secret(pk, sk, ctypes.byref(vault))
    
    # Escribir el vault completo (3488 bytes)
    with open(VAULT_PATH, "wb") as f: f.write(bytes(vault))
    
    # Generar CT original
    lib.generate_ciphertext(pk, ct)
    with open(CT_PATH, "wb") as f: f.write(ct.raw)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST" and request.form.get("action") == "validar_clave":
        return render_template("index.html", step=2, clave=request.form.get("clave"), operacion=request.form.get("operacion"))
    return render_template("index.html", step=1)

@app.route("/ocultar", methods=["POST"])
def ocultar():
    if not os.path.exists(VAULT_PATH): init_crypto()
    
    file_secreto = request.files['file_secreto']
    secreto = bytearray(file_secreto.read())
    
    with open(VAULT_PATH, "rb") as f: vault_data = f.read()
    with open(CT_PATH, "rb") as f: ct_data = f.read()
    
    # Usamos buffer seguro
    vault = PqcVault.from_buffer_copy(vault_data)
    
    lib.vivar_pqc_process(
        (ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto),
        ctypes.c_char_p(ct_data), 1088,
        vault.encrypted_payload, 2400
    )
    
    filename = secure_filename(file_secreto.filename)
    ruta = os.path.join(UPLOAD_FOLDER, filename)
    with open(ruta, "wb") as f: 
        f.write(request.files['file_portador'].read() + SEPARATOR + filename.encode() + META_SEPARATOR + secreto)
    return send_file(ruta, as_attachment=True)

@app.route("/extraer", methods=["POST"])
def extraer():
    if not os.path.exists(VAULT_PATH): return "Error: Sistema no inicializado", 500
    
    archivo_cargado = request.files['file_cargado'].read()
    if SEPARATOR not in archivo_cargado: return "Archivo inválido", 400
    
    partes = archivo_cargado.split(SEPARATOR, 1)
    meta, secreto_cifrado = partes[1].split(META_SEPARATOR, 1)
    secreto = bytearray(secreto_cifrado)
    
    with open(VAULT_PATH, "rb") as f: vault_data = f.read()
    with open(CT_PATH, "rb") as f: ct_data = f.read()
    
    vault = PqcVault.from_buffer_copy(vault_data)
    lib.vivar_pqc_process(
        (ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto),
        ctypes.c_char_p(ct_data), 1088,
        vault.encrypted_payload, 2400
    )
    
    ruta_out = os.path.join(UPLOAD_FOLDER, meta.decode())
    with open(ruta_out, "wb") as f: f.write(secreto)
    return send_file(ruta_out, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
