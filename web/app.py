import os
import sys
import struct
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from vivar_sdk import VivarEngineSDK
    sdk = VivarEngineSDK(lib_path='../target/release/libvivar_engine.so')
except Exception as e:
    sdk = None

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "ejecutar_stego":
            clave = request.form.get("clave", "").encode()
            operacion = request.form.get("operacion")
            file_portador = request.files.get('file_portador')
            
            if not file_portador or not sdk:
                return render_template("index.html", step=2, error="Error de carga.")

            # FORZAMOS EL NOMBRE ORIGINAL AQUÍ
            nombre_final = file_portador.filename
            
            try:
                datos_portador = file_portador.read()
                MARCADOR = b'VIVAR'
                
                if operacion == "cifrar":
                    file_secreto = request.files.get('file_secreto')
                    nombre_secreto = file_secreto.filename.encode('utf-8')
                    cabecera = MARCADOR + struct.pack('B', len(nombre_secreto)) + nombre_secreto
                    payload = sdk.process(file_secreto.read(), clave, offset=0)
                    
                    # Guardar usando estrictamente el nombre original del portador
                    ruta = os.path.join(UPLOAD_FOLDER, nombre_final)
                    with open(ruta, "wb") as f:
                        f.write(datos_portador + cabecera + payload)
                    
                    return render_template("index.html", step=3, archivo_resultante=nombre_final, nombre_descarga=nombre_final)

                elif operacion == "descifrar":
                    pos = datos_portador.find(MARCADOR)
                    if pos == -1: return render_template("index.html", step=2, error="Marcador no encontrado.")
                    
                    inicio_nombre = pos + len(MARCADOR)
                    longitud_nombre = datos_portador[inicio_nombre]
                    nombre_recuperado = datos_portador[inicio_nombre+1 : inicio_nombre+1+longitud_nombre].decode('utf-8')
                    
                    inicio_payload = inicio_nombre + 1 + longitud_nombre
                    res = sdk.decrypt(datos_portador[inicio_payload:], clave, offset=0)
                    
                    ruta = os.path.join(UPLOAD_FOLDER, nombre_recuperado)
                    with open(ruta, "wb") as f: f.write(res)
                    
                    return render_template("index.html", step=3, archivo_resultante=nombre_recuperado, nombre_descarga=nombre_recuperado)
            except Exception as e:
                return render_template("index.html", step=2, error=str(e))
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>/<nombre_descarga>")
def download(filename, nombre_descarga):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True, download_name=nombre_descarga)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
