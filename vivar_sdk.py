import ctypes
import os
from argon2 import PasswordHasher

# Estructura de control para el motor Rust
class VivarBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("len", ctypes.c_size_t)]

class VivarEngineSDK:
    def __init__(self, lib_path: str = "./core/target/release/libcore.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Librería del núcleo no encontrada en: {lib_path}")
            
        self._core = ctypes.CDLL(lib_path)
        # Definición precisa de tipos para evitar errores de segmentación
        self._core.vivar_operator_engine.argtypes = [ctypes.POINTER(VivarBuffer), ctypes.c_char_p, ctypes.c_size_t]
        self._core.generate_pqc_keys.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._core.perform_kem_encapsulation.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        
        self.ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    def generate_keys(self):
        pk = ctypes.create_string_buffer(1184)
        sk = ctypes.create_string_buffer(2400)
        self._core.generate_pqc_keys(ctypes.byref(pk), ctypes.byref(sk))
        return pk.raw, sk.raw

    def create_shared_secret(self, remote_pk: bytes):
        if len(remote_pk) != 1184:
            raise ValueError("Clave pública PQC inválida.")
        ct = ctypes.create_string_buffer(1088)
        ss = ctypes.create_string_buffer(32)
        pk_buf = ctypes.create_string_buffer(remote_pk, 1184)
        self._core.perform_kem_encapsulation(pk_buf, ct, ss)
        return ss.raw

    def execute_mutation(self, data: bytes, secret: bytes) -> bytes:
        """
        Ejecuta la mutación del motor sobre datos binarios (bytes).
        Implementa aislamiento de memoria para proteger la integridad del archivo.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("El motor solo acepta bytes puros.")
            
        # Creamos una copia mutable para no afectar el archivo original en memoria
        mutable_data = bytearray(data)
        data_len = len(mutable_data)
        
        # Buffer de C apuntando a nuestra copia aislada
        data_buf = (ctypes.c_char * data_len).from_buffer(mutable_data)
        buffer = VivarBuffer(ctypes.addressof(data_buf), data_len)
        
        # Buffer de la clave
        key_buf = ctypes.create_string_buffer(secret, len(secret))
        
        # Llamada al núcleo. El resultado muta 'mutable_data' directamente
        res = self._core.vivar_operator_engine(ctypes.byref(buffer), key_buf, len(secret))
        
        if res == 0:
            # Retornamos una copia inmutable de los resultados
            return bytes(mutable_data)
        else:
            raise RuntimeError(f"El motor de cifrado falló con código de error: {res}")
