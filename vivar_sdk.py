import ctypes
import os

class VivarEngineSDK:
    """
    SDK Industrial Vivar Engine - Versión de Precisión Absoluta.
    Comunicación directa de memoria sin estructuras intermedias.
    """
    
    def __init__(self, lib_path: str = "/content/vivar-engine-sdk/target/release/libvivar_engine.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"El núcleo industrial no fue localizado en: {lib_path}")
            
        self._core = ctypes.CDLL(lib_path)
        
        # Firma ajustada: (data_ptr, len, key_ptr, key_len)
        self._core.vivar_operator_engine.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), 
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8), 
            ctypes.c_size_t
        ]
        self._core.vivar_operator_engine.restype = ctypes.c_int

    def process(self, data: bytes, key: bytes) -> bytes:
        # Copia local mutable para asegurar que no haya interferencia
        mutable_data = bytearray(data)
        key_data = bytearray(key)
        
        # Punteros crudos a la memoria
        c_data = (ctypes.c_uint8 * len(mutable_data)).from_buffer(mutable_data)
        c_key = (ctypes.c_uint8 * len(key_data)).from_buffer(key_data)
        
        # Invocación directa: Rust recibe los punteros sin intermediarios
        status = self._core.vivar_operator_engine(
            c_data, len(mutable_data), 
            c_key, len(key_data)
        )
        
        if status != 0:
            raise RuntimeError(f"Error en el motor industrial (Status: {status})")
            
        return bytes(mutable_data)
