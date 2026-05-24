import os
import zlib

class SteganoHandler:
    MARCADOR = b"VIVAR_ENGINE_SECRET_V1"
    
    @staticmethod
    def _comprimir(data: bytes) -> bytes:
        return zlib.compress(data, level=9)

    @staticmethod
    def _descomprimir(data: bytes) -> bytes:
        return zlib.decompress(data)

    @staticmethod
    def ocultar_en_portador(archivo_cifrado: bytes, ruta_portador: str, ruta_salida: str):
        """
        Oculta datos cifrados y comprimidos. 
        Si el archivo ya tiene datos, se sobrescriben o se lanza una advertencia.
        """
        datos_preparados = SteganoHandler._comprimir(archivo_cifrado)
        
        with open(ruta_portador, 'rb') as f:
            contenido_original = f.read()
            
        # Detección: Verificar si el portador ya ha sido utilizado
        if SteganoHandler.MARCADOR in contenido_original:
            raise Exception("El portador ya contiene datos cifrados. Operación abortada.")
            
        with open(ruta_salida, 'wb') as f:
            f.write(contenido_original)
            f.write(SteganoHandler.MARCADOR)
            f.write(datos_preparados)

    @staticmethod
    def extraer_de_portador(ruta_portador: str) -> bytes:
        """
        Extrae, valida y descomprime los datos ocultos.
        """
        with open(ruta_portador, 'rb') as f:
            contenido = f.read()
            
        if SteganoHandler.MARCADOR not in contenido:
            raise ValueError("No se encontraron datos ocultos.")
            
        # Separación y descompresión
        _, datos_comprimidos = contenido.split(SteganoHandler.MARCADOR, 1)
        return SteganoHandler._descomprimir(datos_comprimidos)
