import os
import sys
import shutil

# Ruta del SDK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, send_file
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
# Ruta de almacenamiento de Android (para Termux)
ANDROID_DOWNLOADS = os.path.expanduser("~/storage/downloads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

sdk = VivarEngineSDK(lib_path='../target/release/libvivar_engine.so')

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "validar_clave":
            return render_template("index.html", step=2, clave=request.form.get("clave"), operacion=request.form.get("operacion"))
            
        elif action == "ejecutar_stego":
            clave = request.form.get("clave").encode()
            operacion = request.form.get("operacion")
            file_portador = request.files.get("file_portador")
            nombre_orig = file_portador.filename
            
            try:
                datos = file_portador.read()
                
                if operacion == "cifrar":
                    datos_secreto = request.files.get("file_secreto").read()
                    res = sdk.process(datos_secreto, clave)
                    nombre_g = "MUTATED_" + nombre_orig
                    
                    # 1. Guardar solo en servidor para la web
                    ruta_servidor = os.path.join(UPLOAD_FOLDER, nombre_g)
                    with open(ruta_servidor, "wb") as f: f.write(datos + res)
                    
                    # 2. Copiar a Termux/Android Downloads (Opcional si quieres copia local)
                    if os.path.exists(ANDROID_DOWNLOADS):
                        shutil.copy2(ruta_servidor, os.path.join(ANDROID_DOWNLOADS, nombre_g))
                        
                    return render_template("index.html", step=3, archivo_resultante=nombre_g, nombre_descarga=nombre_orig)
                
                else: # Descifrar
                    res = sdk.decrypt(datos, clave)
                    nombre_g = "RECUPERADO_" + nombre_orig
                    
                    # Guardar archivo para la web
                    ruta_servidor = os.path.join(UPLOAD_FOLDER, nombre_g)
                    with open(ruta_servidor, "wb") as f: f.write(res)
                    
                    # Copiar a Termux/Android Downloads automáticamente
                    if os.path.exists(ANDROID_DOWNLOADS):
                        shutil.copy2(ruta_servidor, os.path.join(ANDROID_DOWNLOADS, nombre_orig))
                        
                    return render_template("index.html", step=3, archivo_resultante=nombre_g, nombre_descarga=nombre_orig)
            
            except Exception as e:
                return render_template("index.html", step=1, error=str(e))
    return render_template("index.html", step=1)

@app.route("/download/<path:filename>/<original_name>")
def download(filename, original_name):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True, download_name=original_name)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
