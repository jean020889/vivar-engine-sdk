import os
import sys
from flask import Flask, render_template, request, send_file

# Asegurar que el SDK sea encontrado
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Instancia única del motor
sdk = VivarEngineSDK(lib_path='../target/release/libvivar_engine.so')

def get_offset(filename):
    ext = os.path.splitext(filename)[1].lower()
    offsets = {'.pdf': 1024, '.jpg': 2048, '.jpeg': 2048, '.png': 1024}
    return offsets.get(ext, 512)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        # PASO 1: Validación de clave inicial
        if action == "validar_clave":
            clave = request.form.get("clave")
            operacion = request.form.get("operacion")
            return render_template("index.html", step=2, clave=clave, operacion=operacion)

        # PASO 2: Ejecución real con archivos
        if action == "ejecutar_stego":
            clave = request.form.get("clave").encode()
            operacion = request.form.get("operacion")
            file_portador = request.files.get('file_portador')
            
            if not file_portador:
                return render_template("index.html", step=1, error="No se recibió el portador.")

            try:
                datos_portador = file_portador.read()
                offset = get_offset(file_portador.filename)
                
                if operacion == "cifrar":
                    file_secreto = request.files.get('file_secreto')
                    if not file_secreto: return render_template("index.html", step=2, error="Falta secreto.")
                    
                    payload = sdk.process(file_secreto.read(), clave, offset)
                    ruta = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                    with open(ruta, "wb") as f: f.write(datos_portador + payload)
                    return render_template("index.html", step=3, archivo_resultante="MUTATED_" + file_portador.filename, nombre_descarga=file_portador.filename)
                
                elif operacion == "descifrar":
                    res = sdk.decrypt(datos_portador, clave, offset)
                    ruta = os.path.join(UPLOAD_FOLDER, "EXTRAIDO_" + file_portador.filename)
                    with open(ruta, "wb") as f: f.write(res)
                    return render_template("index.html", step=3, archivo_resultante="EXTRAIDO_" + file_portador.filename, nombre_descarga="SECRET_" + file_portador.filename)

            except Exception as e:
                return render_template("index.html", step=2, error=str(e))
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>/<nombre_descarga>")
def download(filename, nombre_descarga):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    return send_file(file_path, as_attachment=True, download_name=nombre_descarga)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
