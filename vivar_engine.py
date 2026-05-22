# Vivar Engine SDK - Automated Python Wrapper & Environment Linker v9.9.5
# Connects high-level applications to the native Rust Mutant Core.

import os
import ctypes
import subprocess
import hashlib
import json
import secrets
import time
from typing import Optional

class VivarEngineSDK:
    def __init__(self, rust_project_path: str = "./core"):
        self.rust_path = rust_project_path
        self.lib_path = self._compile_and_locate_core()
        self._core_linker = ctypes.CDLL(self.lib_path)
        
        # Define C-arguments mapping for the Rust function
        self._core_linker.vivar_operator_engine.argtypes = [
            ctypes.c_void_p, # data_ptr
            ctypes.c_size_t, # data_len
            ctypes.c_void_p, # key_ptr
            ctypes.c_size_t  # key_len
        ]
        self._core_linker.vivar_operator_engine.restype = ctypes.c_int32
        
        # Security Debounce mechanism state
        self.last_execution_time = 0.0
        self.debounce_threshold = 2.0 # Seconds required between operations

    def _compile_and_locate_core(self) -> str:
        """Automates Rust native compilation under maximum optimization (opt-level=3)"""
        # Targets standard Linux dynamic library names (.so)
        target_lib = os.path.join(self.rust_path, "target", "release", "libcore.so")
        
        if not os.path.exists(target_lib):
            print("[Vivar SDK] Compiling core native binaries. Please wait...")
            try:
                subprocess.run(
                    ["cargo", "build", "--release"],
                    cwd=self.rust_path,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as e:
                raise RuntimeError(f"Native compilation failed. Is Rust installed? Error: {e}")
        return target_lib

    def derive_key(self, master_key: str, salt: bytes) -> bytes:
        """Post-Quantum PBKDF2-HMAC-SHA512 KDF executing 1,200,000 iterations"""
        return hashlib.pbkdf2_hmac(
            'sha512',
            master_key.encode('utf-8'),
            salt,
            1200000, # Ultra-dense iteration ceiling
            64       # 512-bit key size output
        )

    def execute_mutation(self, data: bytearray, master_key: str) -> Optional[bytearray]:
        """Debounced secure access gateway to execution threads"""
        current_time = time.time()
        if current_time - self.last_execution_time < self.debounce_threshold:
            print("[Vivar SDK Warning] Execution blocked by debounce layer. Operation too frequent.")
            return None
            
        self.last_execution_time = current_time
        
        # Ephemeral salt generation for KDF security
        salt = secrets.token_bytes(16)
        derived_crypto_key = self.derive_key(master_key, salt)
        
        # Convert bytearray to mutable C-compatible data buffer
        data_bytes = bytes(data)
        c_data_buffer = ctypes.create_string_buffer(data_bytes, len(data_bytes))
        c_key_buffer = ctypes.create_string_buffer(derived_crypto_key, len(derived_crypto_key))
        
        # Invoke low-level Rust acceleration loop
        result_code = self._core_linker.vivar_operator_engine(
            ctypes.byref(c_data_buffer),
            len(data_bytes),
            ctypes.byref(c_key_buffer),
            len(derived_crypto_key)
        )
        
        if result_code == 0:
            # Metadata packaging layout for corporate storage compliance
            payload_package = {
                "salt": salt.hex(),
                "payload": c_data_buffer.raw.hex()
            }
            return bytearray(json.dumps(payload_package).encode('utf-8'))
        else:
            raise ValueError(f"Core execution engine panic. Status code: {result_code}")

# SDK Execution Instance initialization placeholder
# sdk_instance = VivarEngineSDK()
