import os
import ctypes
import platform
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'temp_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# MARCADOR DE SEGURIDAD PARA ESTRUCTURA
SEPARATOR = b"###VIVAR_PQC_DATA###"

# --- 1. CONFIGURACIÓN DEL MOTOR ---
ext = ".so" if platform.system() != "Windows" else ".dll"
lib_name = f"libvivar_engine{ext}"
lib_path = os.path.join(BASE_DIR, '..', 'target', 'release', lib_name)
if not os.path.exists(lib_path): lib_path = os.path.join(BASE_DIR, lib_name)

lib = ctypes.CDLL(lib_path)
lib.generate_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.generate_ciphertext.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.vivar_pqc_process.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]

# --- 2. INICIALIZACIÓN ---
def init_crypto():
    pk = ctypes.create_string_buffer(1184)
    sk = ctypes.create_string_buffer(2400)
    ct = ctypes.create_string_buffer(1088)
    lib.generate_keys(pk, sk)
    lib.generate_ciphertext(pk, ct)
    with open("secret.bin", "wb") as f: f.write(sk.raw)
    with open("ciphertext.bin", "wb") as f: f.write(ct.raw)

if not os.path.exists("secret.bin"): init_crypto()

# --- 3. LÓGICA DE NEGOCIO ---
@app.route("/", methods=["POST"])
def index():
    # Acción: OCULTAR
    if request.form.get("action") == "ocultar":
        portador = request.files['file_portador'].read()
        secreto = bytearray(request.files['file_secreto'].read())
        
        secret_key = open("secret.bin", "rb").read()
        ciphertext = open("ciphertext.bin", "rb").read()
        
        # Ciframos solo el secreto
        lib.vivar_pqc_process(
            (ctypes.c_char * len(secreto)).from_buffer(secreto),
            len(secreto), ciphertext, 1088, secret_key, 2400
        )
        
        # Combinamos: Portador + Marcador + Secreto Cifrado
        archivo_final = portador + SEPARATOR + secreto
        
        ruta = os.path.join(UPLOAD_FOLDER, secure_filename(request.files['file_portador'].filename))
        with open(ruta, "wb") as f: f.write(archivo_final)
        return send_file(ruta, as_attachment=True)

    # Acción: EXTRAER
    if request.form.get("action") == "extraer":
        archivo_cargado = request.files['file_cargado'].read()
        if SEPARATOR in archivo_cargado:
            _, secreto_cifrado = archivo_cargado.split(SEPARATOR)
            secreto = bytearray(secreto_cifrado)
            
            secret_key = open("secret.bin", "rb").read()
            ciphertext = open("ciphertext.bin", "rb").read()
            
            # Desciframos (el motor XOR es reversible)
            lib.vivar_pqc_process(
                (ctypes.c_char * len(secreto)).from_buffer(secreto),
                len(secreto), ciphertext, 1088, secret_key, 2400
            )
            
            ruta_out = os.path.join(UPLOAD_FOLDER, "secreto_recuperado")
            with open(ruta_out, "wb") as f: f.write(secreto)
            return send_file(ruta_out, as_attachment=True)

    return "Acción inválida", 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
