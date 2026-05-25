import os
import sys
from flask import Flask, render_template, request, send_file
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Instanciamos el motor Vivar (asegúrate que este SDK use la lógica de delimitador VIVAR001)
sdk = VivarEngineSDK(lib_path='../target/release/libvivar_engine.so')

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        file_portador = request.files.get("file_portador")
        
        # Guardamos el nombre original para evitar perder la referencia
        nombre_original = file_portador.filename
        datos_portador = file_portador.read()
        
        try:
            if action == "cifrar":
                file_secreto = request.files.get("file_secreto")
                datos_secreto = file_secreto.read()
                clave = request.form.get("clave").encode()
                
                # Proceso: El SDK retorna [DATOS_CIFRADOS] + [LONGITUD] + [DELIMITADOR]
                payload = sdk.process(datos_secreto, clave)
                
                ruta_salida = os.path.join(UPLOAD_FOLDER, "MUTATED_" + nombre_original)
                with open(ruta_salida, "wb") as f:
                    f.write(datos_portador + payload)
                    
                return render_template("index.html", step=3, file="MUTATED_" + nombre_original, original=nombre_original)
            
            elif action == "descifrar":
                clave = request.form.get("clave").encode()
                
                # El SDK busca el delimitador y extrae el payload exacto
                datos_recuperados = sdk.decrypt(datos_portador, clave)
                
                # El nombre se asigna explícitamente sin procesamientos extraños
                nombre_salida = "EXTRAIDO_" + nombre_original
                ruta_salida = os.path.join(UPLOAD_FOLDER, nombre_salida)
                
                with open(ruta_salida, "wb") as f:
                    f.write(datos_recuperados)
                    
                return render_template("index.html", step=3, file=nombre_salida, original="documento_secreto.pdf")
                
        except Exception as e:
            return f"Error crítico: {str(e)}"
            
    return render_template("index.html", step=1)

@app.route("/download/<filename>/<original_name>")
def download(filename, original_name):
    # send_file es la forma más segura de servir binarios sin corrupción
    return send_file(
        os.path.join(UPLOAD_FOLDER, filename),
        as_attachment=True,
        download_name=original_name,
        mimetype='application/octet-stream' # Fuerza al navegador a no tocar los bytes
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
