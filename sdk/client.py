import ctypes
import os

class VivarSDK:
    """
    Cliente para interactuar con el motor criptográfico Vivar.
    Gestiona la comunicación con la librería compartida (libvivar_engine.so).
    """
    def __init__(self, lib_path=None):
        # 1. Localización automática del binario compilado
        if lib_path is None:
            # Apuntamos a la ruta donde vimos que se generó el binario en tu sistema
            base_dir = os.path.dirname(os.path.abspath(__file__))
            lib_path = os.path.abspath(os.path.join(base_dir, "../target/release/libvivar_engine.so"))
            
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"No se encuentra el motor nativo en: {lib_path}. Verifica la compilación.")
        
        # 2. Carga de la librería
        self.lib = ctypes.CDLL(lib_path)
        
        # 3. Definición de la firma de la función FFI (Foreign Function Interface)
        # Aseguramos que la firma coincida exactamente con la función en Rust
        self.lib.vivar_operator_engine.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), # data_ptr (mutable)
            ctypes.c_size_t,                # data_len
            ctypes.POINTER(ctypes.c_uint8), # key_ptr (const)
            ctypes.c_size_t,                # key_len
            ctypes.c_uint8                  # mode
        ]
        self.lib.vivar_operator_engine.restype = ctypes.c_int

    def mutar_datos(self, datos: bytes, secreto: bytes, encrypt: bool = True) -> bytes:
        """
        Realiza una mutación de cifrado o descifrado simétrico.
        """
        # Convertimos los bytes en buffers de C compatibles
        data_buf = (ctypes.c_uint8 * len(datos))(*datos)
        key_buf = (ctypes.c_uint8 * len(secreto))(*secreto)
        
        # Modo: 1 para Cifrar, 0 para Descifrar
        mode = 1 if encrypt else 0
        
        # Llamada al motor nativo
        status = self.lib.vivar_operator_engine(
            data_buf, 
            len(datos), 
            key_buf, 
            len(secreto), 
            mode
        )
        
        if status != 0:
            raise RuntimeError(f"El motor Vivar ha retornado un error crítico (Código: {status})")
            
        return bytes(data_buf)

    def cifrar_archivo(self, ruta_entrada: str, ruta_salida: str, secreto: bytes):
        """Utilidad para cifrar archivos completos en disco."""
        with open(ruta_entrada, 'rb') as f:
            datos = f.read()
        
        cifrados = self.mutar_datos(datos, secreto, encrypt=True)
        
        with open(ruta_salida, 'wb') as f:
            f.write(cifrados)

    def descifrar_archivo(self, ruta_entrada: str, ruta_salida: str, secreto: bytes):
        """Utilidad para descifrar archivos completos en disco."""
        with open(ruta_entrada, 'rb') as f:
            datos = f.read()
        
        claros = self.mutar_datos(datos, secreto, encrypt=False)
        
        with open(ruta_salida, 'wb') as f:
            f.write(claros)
