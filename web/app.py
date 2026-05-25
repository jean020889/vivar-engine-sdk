import os
import ctypes
import platform
from flask import Flask, render_template, request, send_file, make_response
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
lib_path = os.path.join(BASE_DIR, '..', 'target', 'release', f"libvivar_engine{ext}")
if not os.path.exists(lib_path): lib_path = os.path.join(BASE_DIR, f"libvivar_engine{ext}")

lib = ctypes.CDLL(lib_path)
lib.vivar_pqc_process.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]

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

@app.route("/ocultar", methods=["POST"])
def ocultar():
    if not os.path.exists(SECRET_PATH): init_crypto()
    
    portador = request.files['file_portador'].read()
    file_secreto = request.files['file_secreto']
    nombre_archivo = file_secreto.filename.encode()
    secreto = bytearray(file_secreto.read())
    
    secret_key = open(SECRET_PATH, "rb").read()
    ciphertext = open(CT_PATH, "rb").read()
    
    lib.vivar_pqc_process((ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto), ciphertext, 1088, secret_key, 2400)
    
    payload = nombre_archivo + META_SEPARATOR + secreto
    
    filename_portador = secure_filename(request.files['file_portador'].filename)
    ruta = os.path.join(UPLOAD_FOLDER, filename_portador)
    with open(ruta, "wb") as f: f.write(portador + SEPARATOR + payload)
    
    response = make_response(send_file(ruta, mimetype="application/octet-stream"))
    response.headers["Content-Disposition"] = f"attachment; filename={filename_portador}"
    return response

@app.route("/extraer", methods=["POST"])
def extraer():
    if not os.path.exists(SECRET_PATH): init_crypto()
    
    archivo_cargado = request.files['file_cargado'].read()
    if SEPARATOR not in archivo_cargado: return "Archivo inválido", 400
    
    # 1. Usamos maxsplit=1 para evitar errores si el archivo contiene el separador
    partes = archivo_cargado.split(SEPARATOR, 1)
    payload = partes[1]
    
    # 2. Separamos el nombre del resto de datos con maxsplit=1
    nombre_original, secreto_cifrado = payload.split(META_SEPARATOR, 1)
    secreto = bytearray(secreto_cifrado)
    
    secret_key = open(SECRET_PATH, "rb").read()
    ciphertext = open(CT_PATH, "rb").read()
    
    # 3. Procesamos SOLO los datos cifrados
    lib.vivar_pqc_process((ctypes.c_char * len(secreto)).from_buffer(secreto), len(secreto), ciphertext, 1088, secret_key, 2400)
    
    ruta_out = os.path.join(UPLOAD_FOLDER, nombre_original.decode())
    with open(ruta_out, "wb") as f: f.write(secreto)
    
    response = make_response(send_file(ruta_out, mimetype="application/octet-stream"))
    response.headers["Content-Disposition"] = f"attachment; filename={nombre_original.decode()}"
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
