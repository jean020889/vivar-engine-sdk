import os
import zlib
import shutil
import tempfile

class SteganoHandler:
    MARCADOR = b"VIVAR_ENGINE_SECRET_V1"
    
    @staticmethod
    def ocultar_en_portador(archivo_cifrado: bytes, ruta_portador: str, ruta_salida: str):
        """
        Oculta datos usando streaming para no cargar el video completo en RAM.
        """
        datos_preparados = zlib.compress(archivo_cifrado, level=9)
        
        # Usamos un archivo temporal para construir el nuevo portador de forma segura
        fd, temp_path = tempfile.mkstemp()
        
        try:
            with open(ruta_portador, 'rb') as f_in, os.fdopen(fd, 'wb') as f_out:
                # 1. Copiar el portador original bloque a bloque (streaming)
                shutil.copyfileobj(f_in, f_out)
                
                # 2. Inyectar marca y datos cifrados/comprimidos
                f_out.write(SteganoHandler.MARCADOR)
                f_out.write(datos_preparados)
            
            # Reemplazar el original con el nuevo archivo procesado
            shutil.move(temp_path, ruta_salida)
            
        except Exception as e:
            if os.path.exists(temp_path): os.remove(temp_path)
            raise e

    @staticmethod
    def extraer_de_portador(ruta_portador: str) -> bytes:
        """
        Extrae datos buscando el marcador al final del archivo.
        """
        with open(ruta_portador, 'rb') as f:
            # Buscar el marcador desde el final del archivo para eficiencia (O(1))
            f.seek(0, os.SEEK_END)
            tamanio = f.tell()
            
            # Leemos los últimos KB buscando el marcador
            busqueda_tam = min(tamanio, 1024 * 1024) # Buscar en los últimos 1MB
            f.seek(-busqueda_tam, os.SEEK_END)
            bloque = f.read()
            
            if SteganoHandler.MARCADOR not in bloque:
                raise ValueError("No se encontraron datos ocultos.")
                
            _, datos_comprimidos = bloque.split(SteganoHandler.MARCADOR, 1)
            return zlib.decompress(datos_comprimidos)
