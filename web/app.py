import os
import sys
import struct
from flask import Flask, render_template, request, send_file

# --- (Inicialización de app y SDK igual) ---

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "ejecutar_stego":
            clave = request.form.get("clave").encode()
            operacion = request.form.get("operacion")
            file_portador = request.files.get('file_portador')
            
            try:
                datos_portador = file_portador.read()
                # Marcador único de 5 bytes para evitar falsos positivos en el video
                MARCADOR = b'VIVAR' 
                
                if operacion == "cifrar":
                    file_secreto = request.files.get('file_secreto')
                    nombre_bytes = file_secreto.filename.encode('utf-8')
                    # Estructura: MARCADOR + LONGITUD_NOMBRE(1 byte) + NOMBRE + PAYLOAD
                    cabecera = MARCADOR + struct.pack('B', len(nombre_bytes)) + nombre_bytes
                    payload = sdk.process(file_secreto.read(), clave, offset=0)
                    
                    ruta = os.path.join(UPLOAD_FOLDER, "MUTATED_" + file_portador.filename)
                    with open(ruta, "wb") as f:
                        f.write(datos_portador)
                        f.write(cabecera)
                        f.write(payload)
                    return render_template("index.html", step=3, archivo_resultante=os.path.basename(ruta), nombre_descarga=file_portador.filename)
                
                elif operacion == "descifrar":
                    # Buscamos el ancla real
                    pos = datos_portador.find(MARCADOR)
                    if pos == -1: 
                        return render_template("index.html", step=2, error="No se encontró contenido oculto (marcador no hallado).")
                    
                    # Saltar el marcador y leer longitud
                    inicio_nombre = pos + len(MARCADOR)
                    longitud_nombre = datos_portador[inicio_nombre]
                    nombre_original = datos_portador[inicio_nombre + 1 : inicio_nombre + 1 + longitud_nombre].decode('utf-8')
                    
                    # El payload empieza después del nombre
                    inicio_payload = inicio_nombre + 1 + longitud_nombre
                    res = sdk.decrypt(datos_portador[inicio_payload:], clave, offset=0)
                    
                    ruta = os.path.join(UPLOAD_FOLDER, nombre_original)
                    with open(ruta, "wb") as f: f.write(res)
                    
                    return render_template("index.html", step=3, archivo_resultante=nombre_original, nombre_descarga=nombre_original)
            except Exception as e:
                return render_template("index.html", step=2, error=f"Error en motor: {str(e)}")
    return render_template("index.html", step=1)
