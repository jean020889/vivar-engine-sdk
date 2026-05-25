import os
import sys

# --- PARCHE DE RUTA ABSOLUTA PARA TERMUX ---
# Esto garantiza que Python encuentre vivar_sdk.py sin importar desde dónde se ejecute
sys.path.append("/data/data/com.termux/files/home/vivar-engine-sdk")

from flask import Flask, render_template, request, send_file
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)

# Configuración de carpetas con rutas absolutas
BASE_DIR = "/data/data/com.termux/files/home/vivar-engine-sdk/web"
UPLOAD_FOLDER = os.path.join(BASE_DIR, "temp_uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Instanciamos el SDK (asegúrate de que el archivo exista en la ruta especificada)
sdk = VivarEngineSDK(lib_path="/data/data/com.termux/files/home/vivar-engine-sdk/target/release/libvivar_engine.so")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        # PASO 1: Validar Clave
        if action == "validar_clave":
            return render_template("index.html", step=2, clave=request.form.get("clave"), operacion=request.form.get("operacion"))
            
        # PASO 2: Ejecutar Procesamiento de Esteganografía
        elif action == "ejecutar_stego":
            clave = request.form.get("clave").encode()
            operacion = request.form.get("operacion")
            file_portador = request.files.get("file_portador")
            
            try:
                datos_portador = file_portador.read()
                
                if operacion == "cifrar":
                    datos_secreto = request.files.get("file_secreto").read()
                    resultado = sdk.process(datos_secreto, clave)
                    output_path = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                    with open(output_path, "wb") as f: 
                        f.write(datos_portador + resultado)
                    return render_template("index.html", step=3, archivo_resultante="MUTATED_" + file_portador.filename, nombre_descarga=file_portador.filename)
                
                else: # Descifrar
                    resultado = sdk.decrypt(datos_portador, clave)
                    output_path = os.path.join(UPLOAD_FOLDER, "RECUPERADO.pdf")
                    with open(output_path, "wb") as f: 
                        f.write(resultado)
                    return render_template("index.html", step=3, archivo_resultante="RECUPERADO.pdf", nombre_descarga="RECUPERADO.pdf")
            
            except Exception as e:
                return render_template("index.html", step=1, error=str(e))

    # GET Inicial (Paso 1)
    return render_template("index.html", step=1)

@app.route("/download/<path:filename>/<original_name>")
def download(filename, original_name):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True, download_name=original_name)

if __name__ == "__main__":
    # Corremos el servidor en todas las interfaces para acceder desde el navegador móvil
    app.run(host="0.0.0.0", port=5000, debug=True)
