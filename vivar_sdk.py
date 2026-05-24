import ctypes
import os

class VivarEngineSDK:
    """
    SDK para la interfaz de comunicación entre Python y el Motor de Cifrado Vivar.
    Optimizado para el motor simétrico involutivo (XOR-Mask 512-bit).
    """
    def __init__(self, lib_path="./target/release/libvivar_engine.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"No se encontró la librería en: {lib_path}")
            
        self._core = ctypes.CDLL(lib_path)
        
        # Firma de la función según el ABI de C definido en lib.rs
        self._core.vivar_operator_engine.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), # data
            ctypes.c_size_t,                # len
            ctypes.POINTER(ctypes.c_uint8), # key
            ctypes.c_size_t                 # key_len
        ]
        self._core.vivar_operator_engine.restype = ctypes.c_int

    def process(self, data: bytes, key: bytes) -> bytes:
        """
        Procesa los datos cifrando o descifrando (Operación Simétrica).
        Aplica padding ISO/IEC 7816-4 para asegurar bloques de 64 bytes.
        """
        # 1. Padding: Asegurar que el buffer sea múltiplo de 64
        pad_len = 64 - (len(data) % 64)
        padded_data = data + b'\x80' + b'\x00' * (pad_len - 1)
        
        # 2. Preparar buffer mutable para C
        buffer = bytearray(padded_data)
        c_data = (ctypes.c_uint8 * len(buffer)).from_buffer(buffer)
        
        # 3. Preparar clave
        c_key = (ctypes.c_uint8 * len(key))(*key)
        
        # 4. Llamada al motor en Rust
        status = self._core.vivar_operator_engine(c_data, len(buffer), c_key, len(key))
        
        if status != 0:
            raise RuntimeError(f"El motor Vivar devolvió un error de estado: {status}")
            
        # 5. Retorno del resultado
        return bytes(buffer)

    def decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Método wrapper para descifrado: aplica el proceso y elimina el padding.
        """
        raw = self.process(encrypted_data, key)
        # Limpiar el marcador 0x80 y sus bytes de relleno
        if b'\x80' in raw:
            return raw.split(b'\x80', 1)[0]
        return raw
