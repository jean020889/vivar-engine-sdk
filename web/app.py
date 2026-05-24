
import os
import sys
import json
from flask import Flask, render_template, request, send_file, redirect, url_for

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
app.secret_key = "vivar_pqc_stego_secret"

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

try:
    sdk = VivarEngineSDK(lib_path="../target/release/libvivar_engine.so")
except:
    sdk = None

@app.route("/", methods=["GET", "POST"])
def index():
    step = 1
    clave = ""
    operacion = "cifrar"
    archivo_resultante = None
    nombre_descarga = "archivo"
    error = None

    if request.method == "POST":
        action = request.form.get("action")
        clave = request.form.get("clave", "")
        operacion = request.form.get("operacion", "cifrar")

        if action == "validar_clave":
            if clave:
                step = 2
            else:
                error = "La clave es obligatoria."
                return render_template("index.html", step=1, error=error)

        elif action == "ejecutar_estego":
            file_secreto = request.files.get("file_secreto")
            file_portador = request.files.get("file_portador")

            if operacion == "cifrar" and (not file_secreto or not file_portador):
                error = "Faltan archivos para procesar."
                return render_template("index.html", step=2, clave=clave, operacion=operacion, error=error)
            if operacion == "descifrar" and not file_portador:
                error = "Falta el archivo portador."
                return render_template("index.html", step=2, clave=clave, operacion=operacion, error=error)

            try:
                clave_bytes = clave.encode("utf-8")
                
                if operacion == "cifrar":
                    path_secreto = os.path.join(app.config['UPLOAD_FOLDER'], file_secreto.filename)
                    path_portador = os.path.join(app.config['UPLOAD_FOLDER'], file_portador.filename)
                    
                    file_secreto.save(path_secreto)
                    file_portador.save(path_portador)

                    # Leer y cifrar el secreto
                    with open(path_secreto, "rb") as f:
                        datos_secreto = f.read()
                    secreto_cifrado = sdk.process(datos_secreto, clave_bytes)

                    # Leer el portador
                    with open(path_portador, "rb") as f:
                        datos_portador = f.read()

                    # Estructura Metadata: Guardamos el nombre original exacto del secreto
                    meta = {"filename": file_secreto.filename}
                    meta_bytes = json.dumps(meta).encode("utf-8")
                    
                    # Estructura del empaquetado esteganográfico al final del portador
                    # [Portador] + [Secreto Cifrado] + [Meta JSON] + [Tam Meta (4B)] + [Tam Secreto (4B)] + [Firma (5B)]
                    tam_secreto_bytes = len(secreto_cifrado).to_bytes(4, byteorder="big")
                    tam_meta_bytes = len(meta_bytes).to_bytes(4, byteorder="big")
                    marca_magica = b"VIVAR"
                    
                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], "output_" + file_portador.filename)
                    with open(output_path, "wb") as f:
                        f.write(datos_portador)
                        f.write(secreto_cifrado)
                        f.write(meta_bytes)
                        f.write(tam_meta_bytes)
                        f.write(tam_secreto_bytes)
                        f.write(marca_magica)

                    os.remove(path_secreto)
                    os.remove(path_portador)

                    step = 3
                    archivo_resultante = "output_" + file_portador.filename
                    nombre_descarga = file_portador.filename

                elif operacion == "descifrar":
                    path_portador = os.path.join(app.config['UPLOAD_FOLDER'], file_portador.filename)
                    file_portador.save(path_portador)

                    with open(path_portador, "rb") as f:
                        datos_totales = f.read()

                    marca_magica = b"VIVAR"
                    if not datos_totales.endswith(marca_magica):
                        os.remove(path_portador)
                        error = "El archivo no contiene ningún secreto detectable."
                        return render_template("index.html", step=2, clave=clave, operacion=operacion, error=error)

                    # Desempaquetar leyendo desde el final de forma exacta para evitar corrupción
                    fin_firma = len(datos_totales) - 5
                    ini_tam_secreto = fin_firma - 4
                    ini_tam_meta = ini_tam_secreto - 4
                    
                    tam_secreto = int.from_bytes(datos_totales[ini_tam_secreto:fin_firma], byteorder="big")
                    tam_meta = int.from_bytes(datos_totales[ini_tam_meta:ini_tam_secreto], byteorder="big")
                    
                    ini_meta = ini_tam_meta - tam_meta
                    ini_secreto = ini_meta - tam_secreto
                    
                    # Extraer bytes puros sin basura sobrante
                    meta_bytes = datos_totales[ini_meta:ini_tam_meta]
                    secreto_cifrado = datos_totales[ini_secreto:ini_meta]

                    # Decodificar nombre original
                    meta_data = json.loads(meta_bytes.decode("utf-8"))
                    nombre_original = meta_data.get("filename", "secreto_recuperado.pdf")

                    # Descifrar en el Core Rust
                    secreto_original = sdk.decrypt(secreto_cifrado, clave_bytes)

                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], "extraido_secreto")
                    with open(output_path, "wb") as f:
                        f.write(secreto_original)

                    os.remove(path_portador)
                    
                    step = 3
                    archivo_resultante = "extraido_secreto"
                    nombre_descarga = nombre_original

            except Exception as e:
                error = f"Fallo en el Core: {str(e)}"
                return render_template("index.html", step=2, clave=clave, operacion=operacion, error=error)

    return render_template("index.html", step=step, clave=clave, operacion=operacion, archivo_resultante=archivo_resultante, nombre_descarga=nombre_descarga, error=error)

@app.route("/download/<filename>/<download_name>")
def download(filename, download_name):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(path):
        response = send_file(path, as_attachment=True, download_name=download_name)
        @response.call_on_close
        def cleanup():
            try:
                os.remove(path)
            except:
                pass
        return response
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
EOF
python app.py
