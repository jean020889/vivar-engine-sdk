import os
import sys
import struct

# Mapeo de rutas
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, send_file
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
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
            
            try:
                datos_portador = file_portador.read()
                nombre_g = "PROCESADO_" + file_portador.filename
                ruta_servidor = os.path.join(UPLOAD_FOLDER, nombre_g)

                if operacion == "cifrar":
                    datos_secreto = request.files.get("file_secreto").read()
                    # El SDK aplica la lógica de delimitador y longitud
                    payload = sdk.process(datos_secreto, clave)
                    
                    with open(ruta_servidor, "wb") as f:
                        f.write(datos_portador + payload)
                        
                    return render_template("index.html", step=3, 
                                           archivo_resultante=nombre_g, 
                                           nombre_descarga=file_portador.filename)
                
                else: # Descifrar
                    # El SDK busca el delimitador y extrae solo el PDF íntegro
                    resultado = sdk.decrypt(datos_portador, clave)
                    nombre_pdf = "EXTRAIDO_" + file_portador.filename.replace(".mp4", ".pdf").replace(".avi", ".pdf")
                    ruta_pdf = os.path.join(UPLOAD_FOLDER, nombre_pdf)
                    
                    with open(ruta_pdf, "wb") as f:
                        f.write(resultado)
                        
                    return render_template("index.html", step=3, 
                                           archivo_resultante=nombre_pdf, 
                                           nombre_descarga="documento_secreto.pdf")
            
            except Exception as e:
                return render_template("index.html", step=1, error=str(e))
                
    return render_template("index.html", step=1)

@app.route("/download/<path:filename>/<original_name>")
def download(filename, original_name):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), 
                     as_attachment=True, 
                     download_name=original_name,
                     mimetype='application/octet-stream')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
