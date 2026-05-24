import ctypes
import os
from argon2 import PasswordHasher

class VivarBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]

class VivarEngineSDK:
    def __init__(self, lib_path: str = "/content/vivar-engine-sdk/target/release/libvivar_engine.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Librería no encontrada en: {lib_path}")
            
        self._core = ctypes.CDLL(lib_path)
        # Ajustado al nombre real de tu función en lib.rs
        self._core.vivar_operator_engine.argtypes = [
            ctypes.POINTER(VivarBuffer), 
            ctypes.POINTER(ctypes.c_uint8), 
            ctypes.c_size_t
        ]
        self.ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    def execute_mutation(self, data: bytes, password: str) -> bytes:
        """
        El motor es simétrico (involutivo). 
        Si el dato está claro, lo cifra. Si está cifrado, lo descifra.
        """
        # 1. Derivación de clave (Nota: Para descifrar necesitarás el mismo salt 
        # que se generó al cifrar. Aquí simplificamos usando una clave derivada fija)
        derived_key = password.encode('utf-8') # Ajusta según tu necesidad de salt
        
        # 2. Preparación
        mutable_data = bytearray(data)
        data_len = len(mutable_data)
        
        # 3. Interfaz con C (Rust)
        data_ptr = (ctypes.c_uint8 * data_len).from_buffer(mutable_data)
        buffer = VivarBuffer(data_ptr, data_len)
        
        key_buf = (ctypes.c_uint8 * len(derived_key)).from_buffer(bytearray(derived_key))
        
        # 4. Invocación
        res = self._core.vivar_operator_engine(ctypes.byref(buffer), key_buf, len(derived_key))
        
        if res == 0:
            return bytes(mutable_data)
        else:
            raise RuntimeError(f"El motor falló con código: {res}")

# --- Ejemplo de uso ---
if __name__ == "__main__":
    try:
        sdk = VivarEngineSDK()
        texto = b"Documento tecnico Alumetal 2026"
        
        # Cifrar
        cifrado = sdk.execute_mutation(texto, "clave123")
        print(f"Cifrado Hex: {cifrado.hex()}")
        
        # Descifrar
        descifrado = sdk.execute_mutation(cifrado, "clave123")
        print(f"Descifrado: {descifrado.decode('utf-8')}")
        
    except Exception as e:
        print(f"Error en el motor: {e}")
