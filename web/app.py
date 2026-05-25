import os
import ctypes
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- 1. Carga Segura del Motor PQC ---
# Corrección de ruta dinámica: sube un nivel desde la carpeta 'web'
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'target', 'release', 'libvivar_engine.so'))

if not os.path.exists(lib_path):
    print(f"ERROR: No se encontró la librería en {lib_path}. Verifica la compilación.")
    exit(1)

lib = ctypes.CDLL(lib_path)
lib.vivar_pqc_process.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t
]
lib.vivar_pqc_process.restype = ctypes.c_int

# --- 2. Lógica de Negocio ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        # PASO 1: Validar clave y avanzar a selección de archivos
        if action == "validar_clave":
            clave = request.form.get("clave")
            operacion = request.form.get("operacion")
            if clave and len(clave) >= 4:
                return render_template("index.html", step=2, clave=clave, operacion=operacion)
            return render_template("index.html", step=1, error="Clave inválida (mínimo 4 caracteres).")

        # PASO 2: Ejecutar el proceso PQC
        if action == "ejecutar_stego":
            file_portador = request.files.get('file_portador')
            clave = request.form.get('clave', '')
            operacion = request.form.get('operacion', 'cifrar')
            
            if not file_portador:
                return render_template("index.html", step=2, error="Debe seleccionar un archivo portador.", clave=clave, operacion=operacion)

            try:
                filename = secure_filename(file_portador.filename)
                portador_data = bytearray(file_portador.read())
                
                # Ejecución PQC
                # Nota: Adaptamos los parámetros a tu lógica de Rust
                status = lib.vivar_pqc_process(
                    (ctypes.c_char * len(portador_data)).from_buffer(portador_data),
                    len(portador_data),
                    clave.encode('ascii'), len(clave),  # Aquí usamos la clave como referencia
                    clave.encode('ascii'), len(clave)   # Ajusta según tu FFI real
                )
                
                if status == 0:
                    ruta = os.path.join(UPLOAD_FOLDER, filename)
                    with open(ruta, "wb") as f:
                        f.write(portador_data)
                    return render_template("index.html", step=3, archivo_resultante=filename)
                else:
                    return render_template("index.html", step=2, error=f"Error en motor PQC (Status: {status})", clave=clave, operacion=operacion)
                    
            except Exception as e:
                return render_template("index.html", step=2, error=f"Fallo técnico: {str(e)}", clave=clave, operacion=operacion)
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, secure_filename(filename)), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
