import ctypes
import os

class VivarBuffer(ctypes.Structure):
    """
    Estructura de memoria compartida para el intercambio de datos 
    entre el SDK Python y el núcleo industrial en Rust.
    """
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]

class VivarEngineSDK:
    """
    SDK Industrial Vivar Engine - Implementación de Alta Seguridad.
    Motor de cifrado simétrico involutivo basado en difusión determinista.
    
    Uso:
    sdk = VivarEngineSDK()
    cifrado = sdk.process(mensaje, llave)
    original = sdk.process(cifrado, llave)
    """
    
    def __init__(self, lib_path: str = "/content/vivar-engine-sdk/target/release/libvivar_engine.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"El núcleo industrial no fue localizado en: {lib_path}")
            
        # Carga del núcleo compilado en Rust
        self._core = ctypes.CDLL(lib_path)
        
        # Firma de la función del motor con tipado estricto
        self._core.vivar_operator_engine.argtypes = [
            ctypes.POINTER(VivarBuffer), 
            ctypes.POINTER(ctypes.c_uint8), 
            ctypes.c_size_t
        ]
        self._core.vivar_operator_engine.restype = ctypes.c_int

    def process(self, data: bytes, key: bytes) -> bytes:
        """
        Ejecuta la mutación industrial (cifrado o descifrado) sobre los datos.
        La operación es involutiva: aplicar el proceso dos veces recupera el original.
        """
        # Preparación de buffers mutables
        mutable_data = bytearray(data)
        key_data = bytearray(key)
        data_len = len(mutable_data)
        
        # Creación de arreglos de C vinculados a los buffers de Python
        # Esto garantiza la integridad y estabilidad de los punteros
        CDataArray = ctypes.c_uint8 * data_len
        CKeyArray = ctypes.c_uint8 * len(key_data)
        
        c_data = CDataArray.from_buffer(mutable_data)
        c_key = CKeyArray.from_buffer(key_data)
        
        # Construcción de la estructura buffer
        buf = VivarBuffer(
            data=ctypes.cast(c_data, ctypes.POINTER(ctypes.c_uint8)), 
            len=data_len
        )
        
        # Invocación al núcleo industrial
        status = self._core.vivar_operator_engine(ctypes.byref(buf), c_key, len(key_data))
        
        if status != 0:
            raise RuntimeError(f"Falla crítica en la mutación industrial. Código: {status}")
            
        return bytes(mutable_data)


