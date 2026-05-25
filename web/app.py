import os
import ctypes
from flask import Flask, render_template, request, send_file

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Cargamos el motor PQC compilado (libvivar_engine.so)
lib_path = os.path.abspath('../target/release/libvivar_engine.so')
lib = ctypes.CDLL(lib_path)

# Definición de la interfaz PQC con Rust
lib.vivar_pqc_process.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t,      # Datos (portador)
    ctypes.c_char_p, ctypes.c_size_t,      # Ciphertext (KEM)
    ctypes.c_char_p, ctypes.c_size_t       # Secret Key (Privada)
]
lib.vivar_pqc_process.restype = ctypes.c_int

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "ejecutar_stego_pqc":
            # Captura de elementos cuánticos del cliente
            file_portador = request.files.get('file_portador')
            # Ciphertext y SecretKey provistos por el cliente tras el handshake Kyber-768
            ciphertext = request.form.get('ciphertext') 
            secret_key = request.form.get('secret_key') 
            
            if not all([file_portador, ciphertext, secret_key]):
                return render_template("index.html", step=2, error="Faltan credenciales cuánticas.")

            # Leer datos en un buffer mutable
            portador_data = bytearray(file_portador.read())
            
            # Ejecución en el motor Rust (Intercambio cuántico interno)
            # El motor realiza el decapsulado y cifra en tiempo constante
            status = lib.vivar_pqc_process(
                (ctypes.c_char * len(portador_data)).from_buffer(portador_data),
                len(portador_data),
                ciphertext.encode(), len(ciphertext),
                secret_key.encode(), len(secret_key)
            )
            
            if status == 0:
                # Guardado seguro del archivo cifrado
                ruta = os.path.join(UPLOAD_FOLDER, file_portador.filename)
                with open(ruta, "wb") as f:
                    f.write(portador_data)
                return render_template("index.html", step=3, archivo=file_portador.filename)
            else:
                return render_template("index.html", step=2, error="Fallo en la sesión cuántica.")
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
