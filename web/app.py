import os
from flask import Flask, render_template, request, send_file
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
# Usamos una ruta absoluta para evitar problemas de permisos en Termux
BASE_DIR = os.path.expanduser("~/vivar-engine-sdk/web")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "temp_uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Instanciamos el SDK (que ya tiene el parche del .rfind en decrypt)
sdk = VivarEngineSDK(lib_path=os.path.expanduser("~/vivar-engine-sdk/target/release/libvivar_engine.so"))

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        clave = request.form.get("clave", "").encode()
        operacion = request.form.get("operacion")
        
        file_secreto = request.files.get("file_secreto")
        file_portador = request.files.get("file_portador")
        
        try:
            if operacion == "cifrar":
                datos_secreto = file_secreto.read()
                datos_portador = file_portador.read()
                
                # Procesamiento mediante el núcleo de Rust
                cifrado = sdk.process(datos_secreto, clave)
                
                # Guardamos el archivo final
                output_path = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                with open(output_path, "wb") as f:
                    f.write(datos_portador + cifrado)
                return f"Archivo cifrado listo: {output_path}"

            elif operacion == "descifrar":
                datos_portador = file_portador.read()
                # Aquí el SDK ya usa el rfind, así que descifrará completo
                secreto_original = sdk.decrypt(datos_portador, clave)
                
                output_path = os.path.join(UPLOAD_FOLDER, "RECUPERADO.pdf")
                with open(output_path, "wb") as f:
                    f.write(secreto_original)
                return send_file(output_path, as_attachment=True)
                
        except Exception as e:
            return f"Error crítico: {str(e)}"
            
    return '''
    <form method="post" enctype="multipart/form-data">
        Clave: <input type="text" name="clave"><br>
        Operación: <select name="operacion"><option value="cifrar">Cifrar</option><option value="descifrar">Descifrar</option></select><br>
        Secreto (PDF): <input type="file" name="file_secreto"><br>
        Portador (Video): <input type="file" name="file_portador"><br>
        <input type="submit" value="Ejecutar">
    </form>
    '''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
