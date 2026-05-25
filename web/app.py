import os
import sys
import struct
from flask import Flask, render_template, request, send_file

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
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

        if action == "ejecutar_stego":
            clave = request.form.get("clave").encode()
            operacion = request.form.get("operacion")
            file_portador = request.files.get('file_portador')
            
            if not file_portador:
                return render_template("index.html", step=2, error="Error: No se recibió el portador.")

            try:
                if operacion == "cifrar":
                    file_secreto = request.files.get('file_secreto')
                    if not file_secreto: return render_template("index.html", step=2, error="Falta secreto.")
                    
                    # 1. Preparar metadatos: [Longitud Nombre (1 byte)][Nombre]
                    nombre_bytes = file_secreto.filename.encode('utf-8')
                    cabecera = struct.pack('B', len(nombre_bytes)) + nombre_bytes
                    
                    # 2. Cifrar
                    payload = sdk.process(file_secreto.read(), clave, offset=0)
                    
                    # 3. Guardar como nuevo archivo
                    ruta = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                    with open(ruta, "wb") as f:
                        f.write(file_portador.read()) # Original intacto
                        f.write(cabecera)             # Metadatos del nombre
                        f.write(payload)              # Secreto cifrado
                        
                    return render_template("index.html", step=3, archivo_resultante=os.path.basename(ruta), nombre_descarga=file_portador.filename)
                
                elif operacion == "descifrar":
                    datos = file_portador.read()
                    
                    # Buscar marcador de inicio (asumiendo que tu SDK pone \x80 antes del payload)
                    inicio_payload = datos.find(b'\x80')
                    if inicio_payload == -1: return render_template("index.html", step=2, error="No se encontró contenido oculto.")
                    
                    # Extraer nombre (el byte anterior al marcador indica la longitud)
                    longitud_nombre = datos[inicio_payload - 1]
                    nombre_original = datos[inicio_payload - longitud_nombre - 1 : inicio_payload].decode('utf-8')
                    
                    # Decifrar
                    res = sdk.decrypt(datos[inicio_payload:], clave, offset=0)
                    
                    ruta = os.path.join(UPLOAD_FOLDER, nombre_original)
                    with open(ruta, "wb") as f: f.write(res)
                    
                    return render_template("index.html", step=3, archivo_resultante=nombre_original, nombre_descarga=nombre_original)

            except Exception as e:
                return render_template("index.html", step=2, error=f"Fallo: {str(e)}")
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>/<nombre_descarga>")
def download(filename, nombre_descarga):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True, download_name=nombre_descarga)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
