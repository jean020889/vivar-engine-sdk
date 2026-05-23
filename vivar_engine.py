# Vivar Engine SDK - Automated Python Wrapper & Environment Linker v9.9.5
import os
import ctypes
import subprocess
import hashlib
import json
import secrets
import time
from typing import Optional

class VivarBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("len", ctypes.c_size_t)]

class VivarEngineSDK:
    def __init__(self, rust_project_path: str = "./core"):
        self.rust_path = rust_project_path
        self.lib_path = self._compile_and_locate_core()
        self._core_linker = ctypes.CDLL(self.lib_path)
        
        # AJUSTE: Ahora vinculamos la función correcta (vivar_crypt_engine)
        # y añadimos el parámetro is_encrypt (uint8)
        self._core_linker.vivar_crypt_engine.argtypes = [
            ctypes.POINTER(VivarBuffer), 
            ctypes.c_char_p, 
            ctypes.c_size_t, 
            ctypes.c_uint8
        ]
        self._core_linker.vivar_crypt_engine.restype = ctypes.c_int32
        
        self.last_execution_time = 0.0
        self.debounce_threshold = 2.0 

    def _compile_and_locate_core(self) -> str:
        # Corregido a la ruta real observada en tu sistema
        target_lib = "./target/release/libcore.so"
        
        if not os.path.exists(target_lib):
            print("[Vivar SDK] Compiling core native binaries...")
            try:
                subprocess.run(["cargo", "build", "--release"], check=True)
            except Exception as e:
                raise RuntimeError(f"Native compilation failed: {e}")
        return target_lib

    def execute_mutation(self, data: bytearray, master_key: str, encrypt: bool = True) -> Optional[bytearray]:
        current_time = time.time()
        if current_time - self.last_execution_time < self.debounce_threshold:
            return None
            
        self.last_execution_time = current_time
        
        # Preparación de buffers
        data_len = len(data)
        data_buf = (ctypes.c_char * data_len).from_buffer(data)
        buffer_struct = VivarBuffer(ctypes.addressof(data_buf), data_len)
        
        # Clave derivada
        derived_key = hashlib.sha256(master_key.encode()).digest()
        key_buf = ctypes.create_string_buffer(derived_key, len(derived_key))
        
        # Ejecución: Pasamos la bandera encrypt (1 para cifrar, 0 para descifrar)
        result_code = self._core_linker.vivar_crypt_engine(
            ctypes.byref(buffer_struct),
            key_buf,
            len(derived_key),
            1 if encrypt else 0
        )
        
        if result_code == 0:
            return data # Los datos fueron mutados in-place
        else:
            raise ValueError(f"Core execution engine panic. Status code: {result_code}")
