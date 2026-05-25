import os
import sys
from flask import Flask, render_template, request, send_file

# Asegurar que el SDK sea encontrado
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

sdk = VivarEngineSDK(lib_path='../target/release/libvivar_engine.so')

def get_offset(filename):
    ext = os.path.splitext(filename)[1].lower()
    # Aumentado el offset para videos (MP4/AVI) para evitar colisión con cabeceras de metadatos
    offsets = {'.pdf': 1024, '.jpg': 2048, '.png': 1024, '.mp4': 8192, '.avi': 8192}
    return offsets.get(ext, 4096)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "validar_clave":
            return render_template("index.html", step=2, clave=request.form.get("clave"), operacion=request.form.get("operacion"))

        if action == "ejecutar_stego":
            clave = request.form.get("clave").encode()
            operacion = request.form.get("operacion")
            file_portador = request.files.get('file_portador')
            
            if not file_portador:
                return render_template("index.html", step=2, error="Error: No se recibió el portador.")

            try:
                # Leemos los datos una sola vez
                datos_portador = file_portador.read()
                offset = get_offset(file_portador.filename)
                
                if operacion == "cifrar":
                    file_secreto = request.files.get('file_secreto')
                    if not file_secreto: return render_template("index.html", step=2, error="Falta archivo secreto.")
                    
                    # El payload cifrado se concatena AL FINAL del archivo portador
                    payload = sdk.process(file_secreto.read(), clave, offset=0)
                    ruta = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                    
                    with open(ruta, "wb") as f:
                        f.write(datos_portador)
                        f.write(payload) # El secreto se añade como un apéndice, no toca el header
                        
                    return render_template("index.html", step=3, archivo_resultante="MUTATED_" + file_portador.filename, nombre_descarga=file_portador.filename)
                
                elif operacion == "descifrar":
                    # Extraemos únicamente el payload añadido al final del archivo
                    # La lógica de VivarEngineSDK debe buscar el marcador de inicio del payload
                    res = sdk.decrypt(datos_portador, clave, offset=0) 
                    ruta = os.path.join(UPLOAD_FOLDER, "EXTRAIDO_" + file_portador.filename)
                    
                    with open(ruta, "wb") as f: f.write(res)
                    return render_template("index.html", step=3, archivo_resultante="EXTRAIDO_" + file_portador.filename, nombre_descarga="SECRET_" + file_portador.filename)

            except Exception as e:
                return render_template("index.html", step=2, error=f"Fallo en el motor: {str(e)}")
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>/<nombre_descarga>")
def download(filename, nombre_descarga):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True, download_name=nombre_descarga)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
