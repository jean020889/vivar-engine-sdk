import os

class SteganoHandler:
    @staticmethod
    def ocultar_en_portador(archivo_cifrado: bytes, ruta_portador: str, ruta_salida: str):
        """
        Oculta los datos cifrados al final del archivo portador.
        Esto permite que el archivo original siga siendo funcional (reproducible).
        """
        with open(ruta_portador, 'rb') as f_portador:
            data_portador = f_portador.read()
            
        with open(ruta_salida, 'wb') as f_salida:
            # Escribimos el portador original
            f_salida.write(data_portador)
            # Añadimos un delimitador mágico (EOF marker) para saber dónde empieza lo oculto
            f_salida.write(b"VIVAR_EOF") 
            # Añadimos los datos cifrados
            f_salida.write(archivo_cifrado)

    @staticmethod
    def extraer_de_portador(ruta_portador: str) -> bytes:
        """
        Extrae los datos ocultos buscando el delimitador.
        """
        with open(ruta_portador, 'rb') as f:
            contenido = f.read()
            
        if b"VIVAR_EOF" in contenido:
            _, datos_ocultos = contenido.split(b"VIVAR_EOF", 1)
            return datos_ocultos
        else:
            raise ValueError("No se encontraron datos ocultos en el portador.")
