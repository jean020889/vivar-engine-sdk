import ctypes
import os

class VivarSDK:
    """
    Cliente para interactuar con el Vivar Encryption Engine (Core en Rust).
    """
    def __init__(self, lib_path=None):
        if lib_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            lib_path = os.path.abspath(os.path.join(base_dir, "../target/release/libcore.so"))
            
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"No se encuentra el binario libcore.so en: {lib_path}")
        
        self.lib = ctypes.CDLL(lib_path)
        
        # --- DEFINICIÓN DE TIPOS (FFI) ---
        
        # vivar_crypt_engine(buffer, key_ptr, key_len, is_encrypt)
        self.lib.vivar_crypt_engine.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint8]
        
        # generate_pqc_keys(pk_out, sk_out)
        self.lib.generate_pqc_keys.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        
        # perform_kem_encapsulation(pk_in, ct_out, ss_out, salt, salt_len)
        self.lib.perform_kem_encapsulation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

    def generar_claves(self):
        pk = ctypes.create_string_buffer(1184)
        sk = ctypes.create_string_buffer(2400)
        self.lib.generate_pqc_keys(pk, sk)
        return pk.raw, sk.raw

    def encapsular(self, pk_bytes, salt=b"vivar-salt-default"):
        pk_buffer = ctypes.create_string_buffer(pk_bytes, 1184)
        ct = ctypes.create_string_buffer(1088)
        ss = ctypes.create_string_buffer(32)
        salt_buffer = ctypes.create_string_buffer(salt)
        
        self.lib.perform_kem_encapsulation(pk_buffer, ct, ss, salt_buffer, len(salt))
        return ct.raw, ss.raw

    def mutar_datos(self, datos: bytes, secreto: bytes, is_encrypt: bool = True) -> bytes:
        class VivarBuffer(ctypes.Structure):
            _fields_ = [("data", ctypes.c_char_p), ("len", ctypes.c_size_t)]
        
        datos_mutable = ctypes.create_string_buffer(datos)
        buf = VivarBuffer(datos_mutable, len(datos))
        
        # Usamos el nombre real: vivar_crypt_engine
        res = self.lib.vivar_crypt_engine(ctypes.byref(buf), secreto, len(secreto), 1 if is_encrypt else 0)
        
        if res != 0:
            raise RuntimeError(f"Error crítico en la mutación Vivar (Código: {res})")
            
        return datos_mutable.raw

# --- Ejemplo de uso ---
if __name__ == "__main__":
    try:
        sdk = VivarSDK()
        print("SDK inicializado. Generando PQC...")
        pk, sk = sdk.generar_claves()
        ct, ss = sdk.encapsular(pk)
        
        mensaje = b"Datos protegidos de Alumetal"
        mutado = sdk.mutar_datos(mensaje, ss, is_encrypt=True)
        
        print(f"Mutación exitosa. Datos: {mutado.hex()}")
    except Exception as e:
        print(f"Error en el SDK: {e}")
