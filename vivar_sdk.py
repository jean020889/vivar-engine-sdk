import ctypes
import os
from argon2 import PasswordHasher

# Estructura de control para el motor Rust
class VivarBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("len", ctypes.c_size_t)]

class VivarEngineSDK:
    def __init__(self, lib_path: str = "./target/release/libcore.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Librería del núcleo no encontrada en: {lib_path}")
            
        self._core = ctypes.CDLL(lib_path)
        
        # CORRECCIÓN: Nombre de función y argumentos actualizados según lib.rs
        # Ahora recibe: VivarBuffer, clave (char*), longitud clave (size_t), modo (u8)
        self._core.vivar_crypt_engine.argtypes = [
            ctypes.POINTER(VivarBuffer), 
            ctypes.c_char_p, 
            ctypes.c_size_t, 
            ctypes.c_uint8
        ]
        
        self._core.generate_pqc_keys.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._core.perform_kem_encapsulation.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
        ]
        
        self.ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    def execute_mutation(self, data: bytes, secret: bytes, encrypt: bool = True) -> bytes:
        """
        Ejecuta la mutación del motor sobre datos binarios (bytes).
        """
        mutable_data = bytearray(data)
        data_len = len(mutable_data)
        
        data_buf = (ctypes.c_char * data_len).from_buffer(mutable_data)
        buffer = VivarBuffer(ctypes.addressof(data_buf), data_len)
        
        key_buf = ctypes.create_string_buffer(secret, len(secret))
        is_encrypt = 1 if encrypt else 0
        
        # Invocamos la función correcta exportada por Rust
        res = self._core.vivar_crypt_engine(ctypes.byref(buffer), key_buf, len(secret), is_encrypt)
        
        if res == 0:
            return bytes(mutable_data)
        else:
            raise RuntimeError(f"El motor de cifrado falló con código: {res}")
