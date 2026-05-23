import os
import shutil

class SteganoHandler:
    @staticmethod
    def procesar(portador_path, datos_cifrados, salida_path):
        """
        Copia el portador original y adjunta los datos cifrados de forma segura.
        """
        # Crear copia para no afectar el archivo original
        shutil.copy2(portador_path, salida_path)
        
        # Adjuntar al final (Append mode)
        with open(salida_path, 'ab') as f:
            # Marcador de inicio (opcional, para identificar datos Vivar al descifrar)
            f.write(b"VIVAR_DATA_START")
            f.write(datos_cifrados)
            f.write(b"VIVAR_DATA_END")
            
        return True

    @staticmethod
    def extraer(archivo_procesado):
        """
        Lee el archivo y extrae solo la parte que contiene los datos cifrados.
        """
        with open(archivo_procesado, 'rb') as f:
            contenido = f.read()
            
        start_tag = b"VIVAR_DATA_START"
        end_tag = b"VIVAR_DATA_END"
        
        if start_tag in contenido and end_tag in contenido:
            return contenido.split(start_tag)[1].split(end_tag)[0]
        return None
      
