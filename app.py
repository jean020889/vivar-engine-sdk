from flask import Flask, request, send_file, jsonify
from vivar_sdk import VivarEngineSDK
import io

app = Flask(__name__)
# Inicializa el SDK (ajusta el path si es necesario)
sdk = VivarEngineSDK()

@app.route('/')
def index():
    return send_file('web/index.html')
    
@app.route('/cifrar', methods=['POST'])
def cifrar():
    if 'archivo' not in request.files:
        return jsonify({"error": "No se envió archivo"}), 400
    
    archivo = request.files['archivo']
    clave = request.form.get('clave', '').encode() # La clave debe ser bytes
    
    # 1. Leer los bytes puros sin procesar
    datos_binarios = archivo.read()
    
    try:
        # 2. Mutación segura mediante el SDK
        # Nota: Aquí asumo que ya tienes una clave o secreto derivado
        resultado = sdk.execute_mutation(datos_binarios, clave)
        
        # 3. Crear el flujo para la descarga
        buffer_salida = io.BytesIO(resultado)
        
        # 4. Enviar como archivo binario puro para evitar corrupción
        return send_file(
            buffer_salida,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=archivo.filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
    
  
