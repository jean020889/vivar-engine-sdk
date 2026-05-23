import os, ctypes, hashlib, json, secrets, time
from typing import Optional

class VivarEngineSDK:
    def __init__(self, rust_project_path: str = "./core"):
        self.rust_path = rust_project_path
        self.lib_path = self._compile_and_locate_core()
        self._core_linker = ctypes.CDLL(self.lib_path)
        
        self._core_linker.vivar_operator_engine.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t
        ]
        self._core_linker.vivar_operator_engine.restype = ctypes.c_int32
        self.last_execution_time = 0.0
        self.debounce_threshold = 1.5 

    def _compile_and_locate_core(self) -> str:
        target_lib = os.path.join(self.rust_path, "target", "release", "libcore.so")
        if not os.path.exists(target_lib):
            print("[Vivar SDK] Compilando Núcleo Mutante PQC...")
            os.system(f"cargo build --release --manifest-path {self.rust_path}/Cargo.toml")
        return target_lib

    def derive_key(self, master_key: str, salt: bytes) -> bytes:
        # KDF de alta densidad: 1.2M iteraciones para resistencia a fuerza bruta
        return hashlib.pbkdf2_hmac('sha512', master_key.encode(), salt, 1200000, 64)

    def execute_mutation(self, data: bytearray, master_key: str) -> Optional[bytearray]:
        if time.time() - self.last_execution_time < self.debounce_threshold:
            return None
            
        self.last_execution_time = time.time()
        salt = secrets.token_bytes(16)
        derived_key = self.derive_key(master_key, salt)
        
        c_data = ctypes.create_string_buffer(bytes(data), len(data))
        c_key = ctypes.create_string_buffer(derived_key, len(derived_key))
        
        res = self._core_linker.vivar_operator_engine(
            ctypes.byref(c_data), len(data), ctypes.byref(c_key), len(derived_key)
        )
        
        if res == 0:
            return bytearray(json.dumps({"salt": salt.hex(), "payload": c_data.raw.hex()}).encode())
        raise RuntimeError("Fallo crítico en el motor mutante.")
      
