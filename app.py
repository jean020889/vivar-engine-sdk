import os
from flask import Flask, request, send_file, jsonify
from vivar_sdk import VivarEngineSDK
import io

app = Flask(__name__)
sdk = VivarEngineSDK()

# Ruta para servir la interfaz web
@app.route('/')
def index():
    return send_file(os.path.join('web', 'index.html'))
    
@app.route('/cifrar', methods=['POST'])
def cifrar():
    # Asegúrate de que tu interfaz envíe el archivo bajo la key 'archivo'
    if 'archivo' not in request.files:
        return jsonify({"error": "No se recibió archivo"}), 400
    
    archivo = request.files['archivo']
    clave = request.form.get('clave', '').encode()
    
    try:
        datos_binarios = archivo.read()
        resultado = sdk.execute_mutation(datos_binarios, clave)
        
        buffer_salida = io.BytesIO(resultado)
        
        # Preservamos el nombre original para evitar sospechas
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
