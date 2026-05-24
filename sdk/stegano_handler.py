import os
import zlib

class SteganoHandler:
    # Marcador hexadecimal único para identificar el inicio de los datos cifrados
    # No es una cadena de texto común para evitar detección simple
    MARCADOR = b"\xDE\xAD\xBE\xEF\x56\x49\x56\x41\x52" 
    
    @staticmethod
    def ocultar_en_portador(archivo_cifrado: bytes, ruta_portador: str):
        """
        Inyecta bytes cifrados al final del archivo portador.
        Mantiene el nombre y la funcionalidad del archivo original.
        """
        # 1. Comprimir para minimizar el impacto en el tamaño del archivo
        datos_preparados = zlib.compress(archivo_cifrado, level=9)
        
        # 2. Inyectar bytes directamente al flujo del portador
        with open(ruta_portador, 'ab') as f_portador:
            f_portador.write(SteganoHandler.MARCADOR)
            f_portador.write(datos_preparados)

    @staticmethod
    def extraer_de_portador(ruta_portador: str) -> bytes:
        """
        Lee el archivo buscando el marcador de bytes para recuperar la data.
        """
        with open(ruta_portador, 'rb') as f:
            contenido = f.read()
            
        if SteganoHandler.MARCADOR not in contenido:
            raise ValueError("El portador no contiene datos ocultos.")
            
        # Extraer mediante el marcador
        _, datos_comprimidos = contenido.split(SteganoHandler.MARCADOR, 1)
        return zlib.decompress(datos_comprimidos)
