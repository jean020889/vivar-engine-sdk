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
                    if not file_secreto: return render_template("index.html", step=2, error="Falta archivo secreto.")
                    
                    datos_portador = file_portador.read()
                    payload = sdk.process(file_secreto.read(), clave, offset=0)
                    
                    ruta = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                    with open(ruta, "wb") as f:
                        f.write(datos_portador)
                        f.write(payload) # Se concatena al final
                        
                    return render_template("index.html", step=3, archivo_resultante="MUTATED_" + file_portador.filename, nombre_descarga=file_portador.filename)
                
                elif operacion == "descifrar":
                    # --- REPARACIÓN AQUÍ: LEEMOS LOS DATOS Y SEPARAMOS EL PAYLOAD ---
                    datos_completos = file_portador.read()
                    
                    # Buscamos el marcador de inicio del payload (debes definir uno en tu SDK)
                    # Por simplicidad, si usamos el padding \x80 del SDK, buscamos el primer \x80
                    inicio_secreto = datos_completos.find(b'\x80')
                    
                    if inicio_secreto == -1:
                        return render_template("index.html", step=2, error="No se encontró contenido oculto.")
                    
                    payload_cifrado = datos_completos[inicio_secreto:]
                    
                    # Deciframos SOLO el payload extraído
                    res = sdk.decrypt(payload_cifrado, clave, offset=0) 
                    
                    ruta = os.path.join(UPLOAD_FOLDER, "RECUPERADO.pdf")
                    with open(ruta, "wb") as f: f.write(res)
                    
                    return render_template("index.html", step=3, archivo_resultante="RECUPERADO.pdf", nombre_descarga="Documento_Oculto.pdf")

            except Exception as e:
                return render_template("index.html", step=2, error=f"Fallo: {str(e)}")
                
    return render_template("index.html", step=1)

@app.route("/download/<filename>/<nombre_descarga>")
def download(filename, nombre_descarga):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True, download_name=nombre_descarga)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
