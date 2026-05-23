# backend_interface.py
import io
import vivar_engine # O la importación correcta de tu sdk

def cifrar_archivo_seguro(file_bytes, clave):
    # Usamos io.BytesIO para evitar que el archivo toque el disco
    # y para mantener la integridad de los bytes
    input_stream = io.BytesIO(file_bytes)
    
    # Aquí llamamos a tu motor. Asegúrate de pasar el buffer, NO el string
    # Ejemplo conceptual:
    return vivar_engine.cifrar(input_stream.getvalue(), clave)
