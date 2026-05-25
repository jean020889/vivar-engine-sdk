import os
import sys

# El código que realmente funcionó usaba la ruta relativa al directorio actual
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, send_file
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# El SDK llamaba al binario directamente
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
            
            try:
                datos_portador = file_portador.read()
                
                if operacion == "cifrar":
                    datos_secreto = request.files.get("file_secreto").read()
                    resultado = sdk.process(datos_secreto, clave)
                    output_path = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                    with open(output_path, "wb") as f: f.write(datos_portador + resultado)
                    return render_template("index.html", step=3, archivo_resultante="MUTATED_" + file_portador.filename, nombre_descarga=file_portador.filename)
                
                else:
                    resultado = sdk.decrypt(datos_portador, clave)
                    output_path = os.path.join(UPLOAD_FOLDER, "RECUPERADO.pdf")
                    with open(output_path, "wb") as f: f.write(resultado)
                    return render_template("index.html", step=3, archivo_resultante="RECUPERADO.pdf", nombre_descarga="RECUPERADO.pdf")
            
            except Exception as e:
                return render_template("index.html", step=1, error=str(e))

    return render_template("index.html", step=1)

@app.route("/download/<path:filename>/<original_name>")
def download(filename, original_name):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True, download_name=original_name)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
