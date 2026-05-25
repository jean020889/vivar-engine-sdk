import os
import ctypes
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Ruta del binario y clave
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'target', 'release', 'libvivar_engine.so'))
key_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'keypair.bin'))

lib = ctypes.CDLL(lib_path)
lib.vivar_pqc_process.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t, # Data
    ctypes.c_char_p, ctypes.c_size_t, # Ciphertext
    ctypes.c_char_p, ctypes.c_size_t  # Secret Key
]
lib.vivar_pqc_process.restype = ctypes.c_int

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "validar_clave":
            return render_template("index.html", step=2)

        if action == "ejecutar_stego":
            file_portador = request.files.get('file_portador')
            
            # Carga de clave real de 1184 bytes (o el tamaño de tu keypair)
            try:
                with open(key_path, "rb") as f:
                    key_data = f.read() # Asumimos que contiene los bytes correctos
                
                portador_data = bytearray(file_portador.read())
                
                # Pasamos los buffers reales al motor
                # ct_dummy es un placeholder hasta que implementes la carga de ciphertext
                ct_dummy = b'\x00' * 1088 
                
                status = lib.vivar_pqc_process(
                    (ctypes.c_char * len(portador_data)).from_buffer(portador_data),
                    len(portador_data),
                    ct_dummy, 1088,
                    key_data, len(key_data)
                )
                
                if status == 0:
                    filename = secure_filename(file_portador.filename)
                    ruta = os.path.join(UPLOAD_FOLDER, filename)
                    with open(ruta, "wb") as f: f.write(portador_data)
                    return render_template("index.html", step=3, archivo_resultante=filename)
                else:
                    return render_template("index.html", step=2, error=f"Fallo PQC (Código {status})")
            except Exception as e:
                return render_template("index.html", step=2, error=str(e))
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
