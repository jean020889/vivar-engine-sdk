import os
import ctypes
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

# --- 1. Configuración de Seguridad ---
app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Carga del motor PQC (libvivar_engine.so)
# Asegúrate de que el binario esté compilado en modo release para máxima optimización
lib_path = os.path.abspath('../target/release/libvivar_engine.so')
lib = ctypes.CDLL(lib_path)

# Definición de la interfaz FFI con Rust (Tipado estricto)
lib.vivar_pqc_process.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t,      # Datos (portador)
    ctypes.c_char_p, ctypes.c_size_t,      # Ciphertext (KEM)
    ctypes.c_char_p, ctypes.c_size_t       # Secret Key (Privada)
]
lib.vivar_pqc_process.restype = ctypes.c_int

# --- 2. Lógica de Negocio ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "ejecutar_stego_pqc":
            # Captura de elementos cuánticos del cliente
            file_portador = request.files.get('file_portador')
            ciphertext = request.form.get('ciphertext', '').strip()
            secret_key = request.form.get('secret_key', '').strip()
            
            # Validación de integridad de los datos de entrada
            if not all([file_portador, ciphertext, secret_key]):
                return render_template("index.html", step=2, error="Credenciales cuánticas incompletas.")

            try:
                # Sanitización del nombre de archivo para prevenir Path Traversal
                filename = secure_filename(file_portador.filename)
                portador_data = bytearray(file_portador.read())
                
                # Ejecución PQC con punteros directos al buffer de memoria
                # El motor realiza el decapsulado y cifra en tiempo constante
                status = lib.vivar_pqc_process(
                    (ctypes.c_char * len(portador_data)).from_buffer(portador_data),
                    len(portador_data),
                    ciphertext.encode('ascii'), len(ciphertext),
                    secret_key.encode('ascii'), len(secret_key)
                )
                
                if status == 0:
                    # Guardado seguro del archivo cifrado en entorno aislado
                    ruta = os.path.join(UPLOAD_FOLDER, filename)
                    with open(ruta, "wb") as f:
                        f.write(portador_data)
                    return render_template("index.html", step=3, archivo=filename)
                else:
                    return render_template("index.html", step=2, error="Error crítico: Fallo de decapsulación PQC.")
                    
            except Exception as e:
                return render_template("index.html", step=2, error=f"Fallo en ejecución: {str(e)}")
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>")
def download(filename):
    # Entrega segura del archivo resultante
    return send_file(os.path.join(UPLOAD_FOLDER, secure_filename(filename)), as_attachment=True)

# --- 3. Despliegue ---
if __name__ == "__main__":
    # Nota: Para entorno industrial, usa un servidor WSGI como Gunicorn/Nginx con TLS 1.3
    app.run(host="0.0.0.0", port=5000, debug=False)
