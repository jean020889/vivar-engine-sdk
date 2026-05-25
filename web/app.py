import os
import sys
from flask import Flask, render_template, request, send_file, make_response

# Asegurar que el SDK sea encontrado
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Instancia única del motor
sdk = VivarEngineSDK(lib_path='../target/release/libvivar_engine.so')

# Función auxiliar para calcular el offset según el formato del portador
def get_offset(filename):
    ext = os.path.splitext(filename)[1].lower()
    # Definimos offsets de seguridad para proteger los encabezados
    offsets = {'.pdf': 1024, '.jpg': 2048, '.jpeg': 2048, '.png': 1024}
    return offsets.get(ext, 512) # Default 512 bytes

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file_portador = request.files.get('file_portador')
        if not file_portador:
            return "Error: No se recibió el archivo portador.", 400

        action = request.form.get("action")
        clave = request.form.get("clave", "").encode()
        
        try:
            datos_portador = file_portador.read()
            offset = get_offset(file_portador.filename)
            
            if action == "cifrar":
                file_secreto = request.files.get('file_secreto')
                if not file_secreto:
                    return "Error: Falta el archivo secreto.", 400
                
                # Pasamos el offset al SDK para que Rust proteja el header
                payload = sdk.process(file_secreto.read(), clave, offset)
                ruta = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                
                with open(ruta, "wb") as f:
                    f.write(datos_portador + payload)
                
                return render_template("index.html", step=3, file="MUTATED_" + file_portador.filename, original=file_portador.filename)
            
            elif action == "descifrar":
                # El descifrado ahora también respeta el offset
                res = sdk.decrypt(datos_portador, clave, offset)
                ruta = os.path.join(UPLOAD_FOLDER, "EXTRAIDO_" + file_portador.filename)
                
                with open(ruta, "wb") as f:
                    f.write(res)
                
                return render_template("index.html", step=3, file="EXTRAIDO_" + file_portador.filename, original=file_portador.filename)
        
        except Exception as e:
            return f"Error en el motor Vivar: {str(e)}", 500
            
    return render_template("index.html", step=1)

@app.route("/download/<filename>/<original>")
def download(filename, original):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    
    # FORZAR descarga segura sin interpretación del navegador
    response = make_response(send_file(file_path, mimetype='application/octet-stream', as_attachment=True, download_name=original))
    
    # Encabezados de seguridad Tier 1
    response.headers["X-Content-Type-Options"] = "nosniff" # Evita que el navegador adivine el tipo de archivo
    response.headers["Content-Disposition"] = f"attachment; filename=\"{original}\""
    
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
