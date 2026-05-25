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

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # 1. Validar que los archivos existan en la petición
        file_portador = request.files.get('file_portador')
        if not file_portador:
            return "Error: No se recibió el archivo portador.", 400

        action = request.form.get("action")
        clave = request.form.get("clave", "").encode()
        
        try:
            datos = file_portador.read()
            
            if action == "cifrar":
                file_secreto = request.files.get('file_secreto')
                if not file_secreto:
                    return "Error: Falta el archivo secreto.", 400
                
                payload = sdk.process(file_secreto.read(), clave)
                ruta = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                with open(ruta, "wb") as f:
                    f.write(datos + payload)
                return render_template("index.html", step=3, file="MUTATED_" + file_portador.filename, original=file_portador.filename)
            
            elif action == "descifrar":
                # 2. Descifrado sin procesar nombres (puro)
                res = sdk.decrypt(datos, clave)
                ruta = os.path.join(UPLOAD_FOLDER, "EXTRAIDO_" + file_portador.filename)
                with open(ruta, "wb") as f:
                    f.write(res)
                return render_template("index.html", step=3, file="EXTRAIDO_" + file_portador.filename, original=file_portador.filename)
        
        except Exception as e:
            return f"Error en el motor Vivar: {str(e)}", 500
            
    return render_template("index.html", step=1)

@app.route("/download/<filename>/<original>")
def download(filename, original):
    # Entrega binaria pura, sin tocar ni un byte
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True, download_name=original)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
