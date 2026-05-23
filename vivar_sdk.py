import ctypes
import os
from argon2 import PasswordHasher

class VivarBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("len", ctypes.c_size_t)]

class VivarEngineSDK:
    def __init__(self, lib_path: str = "./core/target/release/libcore.so"):
        self._core = ctypes.CDLL(lib_path)
        self._core.vivar_operator_engine.argtypes = [ctypes.POINTER(VivarBuffer), ctypes.c_void_p, ctypes.c_size_t]
        self._core.generate_pqc_keys.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._core.perform_kem_encapsulation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    def generate_keys(self):
        pk, sk = ctypes.create_string_buffer(1184), ctypes.create_string_buffer(2400)
        self._core.generate_pqc_keys(pk, sk)
        return pk.raw, sk.raw

    def create_shared_secret(self, remote_pk: bytes):
        ct, ss = ctypes.create_string_buffer(1088), ctypes.create_string_buffer(32)
        self._core.perform_kem_encapsulation(ctypes.create_string_buffer(remote_pk, 1184), ct, ss)
        return ss.raw # Secreto PQC listo para el motor

    def execute_mutation(self, data: bytearray, secret: bytes):
        # Preparación de buffers seguros
        data_buf = (ctypes.c_char * len(data)).from_buffer(data)
        buffer = VivarBuffer(ctypes.addressof(data_buf), len(data))
        key_buf = ctypes.create_string_buffer(secret, len(secret))
        
        # Ejecución del núcleo PQC
        res = self._core.vivar_operator_engine(ctypes.byref(buffer), key_buf, len(secret))
        
        if res == 0:
            return data
        raise RuntimeError("Fallo crítico en el motor mutante PQC.")
      
