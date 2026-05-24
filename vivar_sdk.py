import ctypes
import os

class VivarEngineSDK:
    def __init__(self, lib_path: str = "./target/release/libvivar_engine.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError("Motor no encontrado.")
            
        self._core = ctypes.CDLL(lib_path)
        self._core.vivar_operator_engine.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
        ]
        self._core.vivar_operator_engine.restype = ctypes.c_int

    def _pad(self, data: bytes) -> bytes:
        pad_len = 64 - (len(data) % 64)
        return data + b'\x80' + b'\x00' * (pad_len - 1)

    def _unpad(self, data: bytes) -> bytes:
        return data.rstrip(b'\x00').rstrip(b'\x80')

    def process(self, data: bytes, key: bytes) -> bytes:
        padded = self._pad(data)
        mutable_data = bytearray(padded)
        key_data = bytearray(key)
        
        c_data = (ctypes.c_uint8 * len(mutable_data)).from_buffer(mutable_data)
        c_key = (ctypes.c_uint8 * len(key_data)).from_buffer(key_data)
        
        status = self._core.vivar_operator_engine(c_data, len(mutable_data), c_key, len(key_data))
        if status != 0: raise RuntimeError("Error en el núcleo de seguridad.")
            
        return self._unpad(bytes(mutable_data))
