import os
import sys
import struct
import io
from flask import Flask, render_template, request, send_file

# ... (resto de las importaciones igual)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        # ... (paso 1 igual)

        if action == "ejecutar_stego":
            clave = request.form.get("clave").encode()
            operacion = request.form.get("operacion")
            file_portador = request.files.get('file_portador')
            
            try:
                # Usamos .read() directamente, que devuelve bytes (binario)
                datos_portador = file_portador.read() 
                
                if operacion == "cifrar":
                    file_secreto = request.files.get('file_secreto')
                    nombre_bytes = file_secreto.filename.encode('utf-8')
                    cabecera = struct.pack('B', len(nombre_bytes)) + nombre_bytes
                    
                    # Cifrado en binario puro
                    payload = sdk.process(file_secreto.read(), clave, offset=0)
                    
                    ruta = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                    with open(ruta, "wb") as f:
                        f.write(datos_portador)
                        f.write(cabecera)
                        f.write(payload)
                        
                    return render_template("index.html", step=3, archivo_resultante=os.path.basename(ruta), nombre_descarga=file_portador.filename)
                
                elif operacion == "descifrar":
                    # Buscamos el inicio del payload en los bytes
                    inicio_payload = datos_portador.find(b'\x80')
                    if inicio_payload == -1: 
                        return render_template("index.html", step=2, error="No se encontró contenido oculto.")
                    
                    # Extraemos metadatos en binario
                    longitud_nombre = datos_portador[inicio_payload - 1]
                    nombre_original = datos_portador[inicio_payload - longitud_nombre - 1 : inicio_payload].decode('utf-8')
                    
                    # Deciframos solo el payload (bytes)
                    res = sdk.decrypt(datos_portador[inicio_payload:], clave, offset=0)
                    
                    # Guardamos el archivo final (binario)
                    ruta = os.path.join(UPLOAD_FOLDER, nombre_original)
                    with open(ruta, "wb") as f: f.write(res)
                    
                    return render_template("index.html", step=3, archivo_resultante=nombre_original, nombre_descarga=nombre_original)

            except Exception as e:
                # Si el error persiste, el log mostrará la línea exacta
                return render_template("index.html", step=2, error=f"Fallo binario: {str(e)}")
    return render_template("index.html", step=1)
