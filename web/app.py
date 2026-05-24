import os
import sys
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

                    with open(path_secreto, "rb") as f:
                        datos_secreto = f.read()
                    secreto_cifrado = sdk.process(datos_secreto, clave_bytes)

                    with open(path_portador, "rb") as f:
                        datos_portador = f.read()

                    # Guardar la extensión original del archivo secreto (ej: .pdf, .docx, .png)
                    # Tomamos los últimos 16 caracteres para la extensión como margen seguro
                    ext_original = os.path.splitext(file_secreto.filename)[1].lower().ljust(16)[:16]
                    ext_bytes = ext_original.encode("utf-8")

                    marca_magica = b"VIVAR"
                    tamano_secreto = len(secreto_cifrado).to_bytes(4, byteorder="big")
                    
                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], "output_" + file_portador.filename)
                    with open(output_path, "wb") as f:
                        f.write(datos_portador)
                        f.write(secreto_cifrado)
                        f.write(tamano_secreto)
                        f.write(ext_bytes) # Inyectamos la extensión original de forma oculta
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

                    # Leer estructura desde el final
                    fin_firma = len(datos_totales) - 5
                    ini_ext = fin_firma - 16
                    ini_tamano = ini_ext - 4
                    
                    ext_bytes = datos_totales[ini_ext:fin_firma]
                    ext_detectada = ext_bytes.decode("utf-8", errors="ignore").strip()
                    if not ext_detectada.startswith("."):
                        ext_detectada = ".pdf" # Si no se detecta, se asume PDF por el encabezado

                    tamano_secreto = int.from_bytes(datos_totales[ini_tamano:ini_ext], byteorder="big")
                    
                    ini_secreto = ini_tamano - tamano_secreto
                    secreto_cifrado = datos_totales[ini_secreto:ini_tamano]

                    secreto_original = sdk.decrypt(secreto_cifrado, clave_bytes)

                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], "extraido_secreto")
                    with open(output_path, "wb") as f:
                        f.write(secreto_original)

                    os.remove(path_portador)
                    
                    step = 3
                    archivo_resultante = "extraido_secreto"
                    nombre_descarga = f"secreto_recuperado{ext_detectada}"

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
