import os
import sys
from flask import Flask, render_template, request, flash, redirect

# Asegurar que reconozca el módulo vivar_sdk desde la raíz
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vivar_sdk import VivarEngineSDK

app = Flask(__name__)
app.secret_key = "vivar_web_test_key"

try:
    # Inicializamos tu SDK apuntando al binario compilado
    sdk = VivarEngineSDK(lib_path="../target/release/libvivar_engine.so")
except Exception as e:
    sdk = None
    print(f"⚠️ Alerta: No se cargó el SDK nativo, verifica la compilación: {e}")

@app.route("/", methods=["GET", "POST"])
def index():
    resultado = None
    estado = None

    if request.method == "POST":
        opcion = request.form.get("opcion")
        ruta = request.form.get("ruta")
        key_str = request.form.get("key")

        if not os.path.exists(ruta):
            estado = "❌ El archivo no existe en la ruta especificada."
            return render_template("index.html", resultado=resultado, estado=estado)

        if not key_str:
            estado = "❌ La clave criptográfica es obligatoria."
            return render_template("index.html", resultado=resultado, estado=estado)

        try:
            clave_bytes = key_str.encode("utf-8")
            
            # Leer el archivo real del celular (/sdcard/...)
            with open(ruta, "rb") as f:
                datos_originales = f.read()

            if opcion == "cifrar":
                datos_procesados = sdk.process(datos_originales, clave_bytes)
                nueva_ruta = ruta + ".vivar"
                accion = "Cifrado"
            else:
                datos_procesados = sdk.decrypt(datos_originales, clave_bytes)
                nueva_ruta = ruta[:-6] if ruta.endswith(".vivar") else ruta + ".dec"
                accion = "Descifrado"

            # Escribir el resultado directamente en el almacenamiento del celular
            with open(nueva_ruta, "wb") as f:
                f.write(datos_procesados)

            estado = f"✅ {accion} exitoso. Archivo guardado en:\n{nueva_ruta}"
        except Exception as e:
            estado = f"❌ Error en el motor: {str(e)}"

    return render_template("index.html", resultado=resultado, estado=estado)

if __name__ == "__main__":
    # Correr en el puerto 5000 de forma local
    app.run(host="127.0.0.1", port=5000, debug=True)
