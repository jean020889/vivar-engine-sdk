import os
import ctypes
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Carga del motor PQC
lib_path = os.path.abspath('./target/release/libvivar_engine.so')
lib = ctypes.CDLL(lib_path)
lib.vivar_pqc_process.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t
]
lib.vivar_pqc_process.restype = ctypes.c_int

# --- Lógica de Rutas ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        # PASO 1: Validar Clave -> Pasar a STEP 2
        if action == "validar_clave":
            clave = request.form.get("clave")
            operacion = request.form.get("operacion")
            if clave and len(clave) >= 4:
                return render_template("index.html", step=2, clave=clave, operacion=operacion)
            return render_template("index.html", step=1, error="Clave inválida.")

        # PASO 2: Ejecutar Proceso -> Pasar a STEP 3
        if action == "ejecutar_stego":
            file_portador = request.files.get('file_portador')
            # Aquí ajustamos para usar tu motor según el flujo real de datos
            # ... tu lógica actual de lib.vivar_pqc_process ...
            if file_portador:
                filename = secure_filename(file_portador.filename)
                # ... (resto de tu lógica de procesamiento)
                return render_template("index.html", step=3, archivo_resultante=filename)

    return render_template("index.html", step=1)

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, secure_filename(filename)), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
