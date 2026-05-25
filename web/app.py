import os
import sys
import json
import hashlib
from flask import Flask, render_template, request, Response, redirect, url_for, stream_with_context

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

def generar_firma_estatica(clave_texto):
    """Deriva la firma de alineación geométrica basada en tu clave de seguridad"""
    salt = b"VIVAR_PRO_2026_ESTATAL_777"
    derived = hashlib.pbkdf2_hmac('sha512', clave_texto.encode(), salt, 1200000, 64)
    kh = hashlib.sha512(derived + salt).digest()
    sig = hashlib.sha256(kh + b"SIG942").digest()[:16]
    return sig

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

        elif action == "ejecutar_stego":
            file_secreto = request.files.get("file_secreto")
            file_portador = request.files.get("file_portador")

            if operacion == "cifrar" and (not file_secreto or not file_portador):
                error = "Faltan archivos para procesar."
                return render_template("index.html", step=2, clave=clave, operacion=operacion, error=error)
            if operacion == "descifrar" and not file_portador:
                error = "Falta el archivo portador."
                return render_template("index.html", step=2, clave=clave, operacion=operacion, error=error)

            try:
                sig = generar_firma_estatica(clave)
                clave_bytes = clave.encode("utf-8")
                
                if operacion == "cifrar":
                    path_secreto = os.path.join(app.config['UPLOAD_FOLDER'], file_secreto.filename)
                    path_portador = os.path.join(app.config['UPLOAD_FOLDER'], file_portador.filename)
                    
                    file_secreto.save(path_secreto)
                    file_portador.save(path_portador)

                    with open(path_secreto, "rb") as f:
                        datos_secreto = f.read()
                    
                    # 1. Cifrado nativo puro con el Core de Rust (Aislado de metadatos)
                    secreto_cifrado = sdk.process(datos_secreto, clave_bytes)

                    with open(path_portador, "rb") as f:
                        datos_portador = f.read()

                    # 2. Empaquetado lineal milimétrico
                    meta = json.dumps({"filename": file_secreto.filename}).encode('utf-8')
                    
                    tam_secreto_bytes = len(secreto_cifrado).to_bytes(4, byteorder="big")
                    tam_meta_bytes = len(meta).to_bytes(4, byteorder="big")
                    
                    output_filename = "output_" + file_portador.filename
                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
                    
                    # Estructura limpia: [PORTADOR] + [FIRMA] + [CIFRADO] + [META] + [TAM_META] + [TAM_SECRETO]
                    with open(output_path, "wb") as f:
                        f.write(datos_portador)
                        f.write(sig)
                        f.write(secreto_cifrado)
                        f.write(meta)
                        f.write(tam_meta_bytes)
                        f.write(tam_secreto_bytes)

                    os.remove(path_secreto)
                    os.remove(path_portador)

                    return render_template("index.html", step=3, archivo_resultante=output_filename, nombre_descarga=file_portador.filename)

                elif operacion == "descifrar":
                    path_portador = os.path.join(app.config['UPLOAD_FOLDER'], file_portador.filename)
                    file_portador.save(path_portador)

                    with open(path_portador, "rb") as f:
                        datos_totales = f.read()

                    # BÚSQUEDA DINÁMICA DE LA ALINEACIÓN POR FIRMA GEOMÉTRICA
                    idx = datos_totales.find(sig)
                    if idx == -1:
                        os.remove(path_portador)
                        error = "Alineación defectuosa: Firma no encontrada o clave incorrecta."
                        return render_template("index.html", step=2, clave=clave, operacion=operacion, error=error)

                    # Extraer las longitudes estrictas desde los últimos 8 bytes del archivo total
                    # Evitamos desfases leyendo de atrás hacia adelante con respecto al final del bloque
                    fin_bloque = len(datos_totales)
                    tam_secreto = int.from_bytes(datos_totales[fin_bloque-4:fin_bloque], byteorder="big")
                    tam_meta = int.from_bytes(datos_totales[fin_bloque-8:fin_bloque-4], byteorder="big")
                    
                    # Delimitar las zonas exactas basadas en el punto de inicio de la firma
                    ini_secreto = idx + 16
                    fin_secreto = ini_secreto + tam_secreto
                    ini_meta = fin_secreto
                    fin_meta = ini_meta + tam_meta
                    
                    # Extracción exacta de bytes
                    secreto_cifrado_puro = datos_totales[ini_secreto:fin_secreto]
                    meta_bytes = datos_totales[ini_meta:fin_meta]
                    
                    meta_data = json.loads(meta_bytes.decode('utf-8'))
                    nombre_original = meta_data.get("filename", "recuperado.pdf")
                    
                    # Descifrado nativo sin colas ni padding corrupto
                    secreto_original = sdk.decrypt(bytes(secreto_cifrado_puro), clave_bytes)

                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], nombre_original)
                    with open(output_path, "wb") as f:
                        f.write(secreto_original)

                    os.remove(path_portador)
                    
                    return render_template("index.html", step=3, archivo_resultante=nombre_original, nombre_descarga=nombre_original)

            except Exception as e:
                error = f"Error en alineación de punteros: {str(e)}"
                return render_template("index.html", step=2, clave=clave, operacion=operacion, error=error)

    return render_template("index.html", step=step, clave=clave, operacion=operacion, archivo_resultante=archivo_resultante, nombre_descarga=nombre_descarga, error=error)

@app.route("/download/<filename>/<download_name>")
def download(filename, download_name):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(path):
        def generate():
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(16384)
                    if not chunk:
                        break
                    yield chunk
        
        headers = {
            "Content-Disposition": f'attachment; filename="{download_name}"',
            "Content-Length": str(os.path.getsize(path)),
            "X-Content-Type-Options": "nosniff"
        }
        return Response(stream_with_context(generate()), mimetype="application/octet-stream", headers=headers)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
EOF

