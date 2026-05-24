cd ~/vivar-engine-sdk/web && cat << 'EOF' > app.py
import os
import sys
from flask import Flask, render_template, request, send_file, flash, redirect, url_for

# Configuración de rutas para el SDK
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
app.secret_key = "vivar_pqc_stego_secret"

# Carpeta temporal para procesar las cargas del celular
UPLOAD_FOLDER = "/tmp/vivar_web"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

try:
    sdk = VivarEngineSDK(lib_path="../target/release/libvivar_engine.so")
except Exception as e:
    sdk = None

@app.route("/", methods=["GET", "POST"])
def index():
    # Control del estado del flujo en la pantalla
    step = 1
    clave = ""
    operacion = "cifrar"
    archivo_resultante = None
    nombre_descarga = "archivo"

    if request.method == "POST":
        action = request.form.get("action")
        clave = request.form.get("clave", "")
        operacion = request.form.get("operacion", "cifrar")

        if action == "validar_clave":
            if clave:
                step = 2  # Habilitar subida de archivos
            else:
                return render_template("index.html", step=1, error="La clave es obligatoria.")

        elif action == "ejecutar_estego":
            # Capturar los archivos desde los botones nativos de Android
            file_secreto = request.files.get("file_secreto")
            file_portador = request.files.get("file_portador")

            if operacion == "cifrar" and (not file_secreto or not file_portador):
                return render_template("index.html", step=2, clave=clave, operacion=operacion, error="Faltan archivos para procesar.")
            if operacion == "descifrar" and not file_portador:
                return render_template("index.html", step=2, clave=clave, operacion=operacion, error="Falta el archivo portador para extraer.")

            try:
                clave_bytes = clave.encode("utf-8")
                
                if operacion == "cifrar":
                    # Rutas temporales de procesamiento
                    path_secreto = os.path.join(app.config['UPLOAD_FOLDER'], file_secreto.filename)
                    path_portador = os.path.join(app.config['UPLOAD_FOLDER'], file_portador.filename)
                    
                    file_secreto.save(path_secreto)
                    file_portador.save(path_portador)

                    # 1. Cifrar el archivo secreto con Vivar Engine
                    with open(path_secreto, "rb") as f:
                        datos_secreto = f.read()
                    secreto_cifrado = sdk.process(datos_secreto, clave_bytes)

                    # 2. Leer portador original
                    with open(path_portador, "rb") as f:
                        datos_portador = f.read()

                    # 3. Inyección Esteganográfica Limpia al final del portador
                    # Estructura: [Datos Portador] + [Datos Secretos Cifrados] + [Tamaño del Secreto (4 bytes)] + [Firma Mágica]
                    marca_magica = b"VIVAR"
                    tamano_secreto = len(secreto_cifrado).to_bytes(4, byteorder="big")
                    
                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], "output_" + file_portador.filename)
                    with open(output_path, "wb") as f:
                        f.write(datos_portador)
                        f.write(secreto_cifrado)
                        f.write(tamano_secreto)
                        f.write(marca_magica)

                    # Limpieza de temporales individuales
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

                    # Verificar si contiene nuestra firma esteganográfica al final
                    marca_magica = b"VIVAR"
                    if not datos_totales.endswith(marca_magica):
                        os.remove(path_portador)
                        return render_template("index.html", step=2, clave=clave, operacion=operacion, error="El archivo no contiene ningún secreto oculto detectable.")

                    # Leer tamaño del secreto y extraer los bytes correspondientes
                    fin_firma = len(datos_totales) - 5
                    ini_tamano = fin_firma - 4
                    tamano_secreto = int.from_bytes(datos_totales[ini_tamano:fin_firma], byteorder="big")
                    
                    ini_secreto = ini_tamano - tamano_secreto
                    secreto_cifrado = datos_totales[ini_secreto:ini_tamano]

                    # Descifrar usando Vivar Engine
                    secreto_original = sdk.decrypt(secreto_cifrado, clave_bytes)

                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], "extraido_secreto")
                    with open(output_path, "wb") as f:
                        f.write(secreto_original)

                    os.remove(path_portador)
                    
                    step = 3
                    archivo_resultante = "extraido_secreto"
                    # Intenta recuperar un nombre genérico o pide guardarlo
                    nombre_descarga = "secreto_recuperado.bin"

            except Exception as e:
                return render_template("index.html", step=2, clave=clave, operacion=operacion, error=f"Fallo en el Core: {str(e)}")

    return render_template("index.html", step=step, clave=clave, operacion=operacion, archivo_resultante=archivo_resultante, nombre_descarga=nombre_descarga)

@app.route("/download/<filename>/<download_name>")
def download(filename, download_name):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(path):
        # Envía el archivo con su nombre original exacto y sin alterar extensiones
        response = send_file(path, as_attachment=True, download_name=download_name)
        
        # Eliminar el archivo del servidor local después de enviarlo para mayor seguridad
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
