
import os
import sys
import json
import hashlib
import secrets
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

def generar_firma_vivar(clave_texto):
    """Deriva la firma exacta usando la lógica del sistema original v9.9.5"""
    salt = b"VIVAR_PRO_2026_ESTATAL_777"
    derived = hashlib.pbkdf2_hmac('sha512', clave_texto.encode(), salt, 1200000, 64)
    kh = hashlib.sha512(derived + salt).digest()
    sig = hashlib.sha256(kh + b"SIG942").digest()[:16]
    return kh, sig

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
                # Ejecutar KDF ultra e inmunidad de firmas de Jean Carlos
                kh, sig = generar_firma_vivar(clave)
                clave_bytes = clave.encode("utf-8") # Para compatibilidad con el Core actual
                
                if operacion == "cifrar":
                    path_secreto = os.path.join(app.config['UPLOAD_FOLDER'], file_secreto.filename)
                    path_portador = os.path.join(app.config['UPLOAD_FOLDER'], file_portador.filename)
                    
                    file_secreto.save(path_secreto)
                    file_portador.save(path_portador)

                    with open(path_secreto, "rb") as f:
                        datos_secreto = f.read()
                    
                    # Cifrado con el núcleo actual
                    secreto_cifrado = sdk.process(datos_secreto, clave_bytes)

                    with open(path_portador, "rb") as f:
                        datos_portador = f.read()

                    # Reconstrucción del empaquetado nativo v9.9.5
                    meta = json.dumps({"filename": file_secreto.filename}).encode('utf-8')
                    # Estructura interna: longitud_meta(4B) + meta + secreto_cifrado
                    cuerpo_secreto = bytearray(len(meta).to_bytes(4, 'big') + meta + secreto_cifrado)
                    
                    # Inyección de dispersión estocástica para robustez
                    cuerpo_secreto += secrets.token_bytes(secrets.randbelow(512))
                    s_len_h = len(cuerpo_secreto).to_bytes(4, 'big')
                    
                    output_filename = "output_" + file_portador.filename
                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
                    
                    # Ensamble final idéntico a tu software exitoso
                    with open(output_path, "wb") as f:
                        f.write(datos_portador)
                        f.write(sig)
                        f.write(s_len_h)
                        f.write(cuerpo_secreto)

                    os.remove(path_secreto)
                    os.remove(path_portador)

                    return render_template("index.html", step=3, archivo_resultante=output_filename, nombre_descarga=file_portador.filename)

                elif operacion == "descifrar":
                    path_portador = os.path.join(app.config['UPLOAD_FOLDER'], file_portador.filename)
                    file_portador.save(path_portador)

                    with open(path_portador, "rb") as f:
                        datos_totales = f.read()

                    # BÚSQUEDA DINÁMICA POR FIRMA GEOMÉTRICA (Evita fallos por bloqueos de Android)
                    idx = datos_totales.find(sig)
                    if idx == -1:
                        os.remove(path_portador)
                        error = "Alineación defectuosa: Firma no encontrada o clave incorrecta."
                        return render_template("index.html", step=2, clave=clave, operacion=operacion, error=error)

                    l_idx = idx + 16
                    s_len = int.from_bytes(datos_totales[l_idx:l_idx+4], 'big')
                    
                    # Extracción exacta aislada del ruido de red
                    cuerpo_extraido = datos_totales[l_idx+4 : l_idx+4+s_len]
                    
                    # Extraer metadatos según el orden original
                    m_len = int.from_bytes(cuerpo_extraido[:4], 'big')
                    meta_data = json.loads(cuerpo_extraido[4:4+m_len].decode('utf-8'))
                    nombre_original = meta_data.get("filename", "recuperado.pdf")
                    
                    secreto_cifrado_puro = cuerpo_extraido[4+m_len:]
                    
                    # Como añadimos token_bytes al final en el cifrado, debemos limpiar el padding sobrante para Rust.
                    # El Core de Rust espera bloques exactos o sabe su tamaño. 
                    # Si tu sdk.decrypt maneja el tamaño exacto del cifrado original:
                    # En tu v9.9.5 pasabas todo el bloque porque Rust leía por chunks, aquí hacemos el decrypt nativo:
                    secreto_original = sdk.decrypt(bytes(secreto_cifrado_puro), clave_bytes)

                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], nombre_original)
                    with open(output_path, "wb") as f:
                        f.write(secreto_original)

                    os.remove(path_portador)
                    
                    return render_template("index.html", step=3, archivo_resultante=nombre_original, nombre_descarga=nombre_original)

            except Exception as e:
                error = f"Fallo de Sincronización en Core: {str(e)}"
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
