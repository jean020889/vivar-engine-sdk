import ctypes
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# --- Estructura de control para el motor Rust ---
class VivarBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("len", ctypes.c_size_t)]

class VivarEngineSDK:
    def __init__(self, lib_path: str = "./target/release/libcore.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Librería del núcleo no encontrada en: {lib_path}")
            
        self._core = ctypes.CDLL(lib_path)
        
        # Configuración de firmas de funciones
        self._core.vivar_crypt_engine.argtypes = [
            ctypes.POINTER(VivarBuffer), 
            ctypes.c_char_p, 
            ctypes.c_size_t, 
            ctypes.c_uint8
        ]
        
        # Hasher Argon2id para derivación de claves segura (Hardened)
        self.ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    def _apply_pkcs7_padding(self, data: bytes, block_size: int = 16) -> bytes:
        """Asegura que los datos sean múltiplos del bloque para evitar desbordes."""
        padding = block_size - (len(data) % block_size)
        return data + bytes([padding] * padding)

    def execute_mutation(self, data: bytes, password: str, encrypt: bool = True) -> bytes:
        """
        Flujo: Derivación Argon2 -> Padding -> Mutación en Rust -> Limpieza de memoria.
        """
        # 1. Derivación de clave segura
        # Nota: En producción, guarda el salt junto al archivo cifrado
        derived_key = self.ph.hash(password).encode('utf-8')
        
        # 2. Preparación de datos
        padded_data = self._apply_pkcs7_padding(data) if encrypt else data
        mutable_data = bytearray(padded_data)
        data_len = len(mutable_data)
        
        # 3. Interfaz con C (Rust)
        data_buf = (ctypes.c_char * data_len).from_buffer(mutable_data)
        buffer = VivarBuffer(ctypes.addressof(data_buf), data_len)
        
        key_buf = ctypes.create_string_buffer(derived_key, len(derived_key))
        is_encrypt = 1 if encrypt else 0
        
        # 4. Invocación de la función nativa
        res = self._core.vivar_crypt_engine(ctypes.byref(buffer), key_buf, len(derived_key), is_encrypt)
        
        # 5. Limpieza crítica de memoria
        for i in range(len(key_buf)): key_buf[i] = 0
        
        if res == 0:
            return bytes(mutable_data)
        else:
            raise RuntimeError(f"El motor falló con código de error interno: {res}")

# --- Ejemplo de uso ---
if __name__ == "__main__":
    try:
        sdk = VivarEngineSDK()
        # Ejemplo: cifrado de un archivo
        with open("archivo_secreto.txt", "rb") as f:
            contenido = f.read()
            
        cifrado = sdk.execute_mutation(contenido, "mi_clave_maestra_1000", encrypt=True)
        
        with open("archivo_cifrado.bin", "wb") as f:
            f.write(cifrado)
            
        print("Operación completada con éxito.")
    except Exception as e:
        print(f"Error en el motor: {e}")
