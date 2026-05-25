import os
import ctypes
from flask import Flask, render_template, request, send_file

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Carga del motor PQC (libvivar_engine.so compilado con Kyber-768)
lib_path = os.path.abspath('../target/release/libvivar_engine.so')
lib = ctypes.CDLL(lib_path)

# Definición de la interfaz con Rust
lib.vivar_pqc_process.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t, 
    ctypes.c_char_p, ctypes.c_size_t, 
    ctypes.c_char_p, ctypes.c_size_t
]
lib.vivar_pqc_process.restype = ctypes.c_int

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "ejecutar_stego_pqc":
            # Captura de elementos cuánticos (Zero-Knowledge)
            file_portador = request.files.get('file_portador')
            ciphertext = request.form.get('ciphertext') # Base64
            secret_key = request.form.get('secret_key') # Base64
            
            if not file_portador or not ciphertext or not secret_key:
                return "Error: Credenciales cuánticas faltantes", 400

            portador_data = bytearray(file_portador.read())
            
            # Procesamiento PQC en el motor Rust (Zero-Knowledge)
            status = lib.vivar_pqc_process(
                (ctypes.c_char * len(portador_data)).from_buffer(portador_data),
                len(portador_data),
                ciphertext.encode(), len(ciphertext),
                secret_key.encode(), len(secret_key)
            )
            
            if status == 0:
                ruta = os.path.join(UPLOAD_FOLDER, file_portador.filename)
                with open(ruta, "wb") as f:
                    f.write(portador_data)
                return render_template("index.html", step=3, archivo_resultante=file_portador.filename)
            else:
                return "Error en desencapsulación PQC", 500

    return render_template("index.html", step=1)

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
