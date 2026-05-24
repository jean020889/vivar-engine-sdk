import ctypes
import os

class VivarSDK:
    """
    Cliente para interactuar con el Vivar Encryption Engine (Core en Rust).
    """
    def __init__(self, lib_path=None):
        # Localiza el binario compilado automáticamente
        if lib_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            lib_path = os.path.abspath(os.path.join(base_dir, "../target/release/libcore.so"))
            
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"No se encuentra el binario libcore.so en: {lib_path}")
        
        # Carga la librería compartida
        self.lib = ctypes.CDLL(lib_path)
        
        # --- DEFINICIÓN DE TIPOS (FFI) ---
        # Aseguramos que la firma coincida con el motor Rust
        self.lib.vivar_crypt_engine.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint8
        ]
        self.lib.generate_pqc_keys.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p
        ]
        self.lib.perform_kem_encapsulation.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
        ]

    def generar_claves(self):
        """Genera par de claves Kyber768 (pk, sk)."""
        pk = ctypes.create_string_buffer(1184)
        sk = ctypes.create_string_buffer(2400)
        self.lib.generate_pqc_keys(pk, sk)
        return pk.raw, sk.raw

    def encapsular(self, pk_bytes, salt=b"vivar-salt-default"):
        """Encapsula clave pública PQC usando un salt."""
        pk_buffer = ctypes.create_string_buffer(pk_bytes, 1184)
        ct = ctypes.create_string_buffer(1088)
        ss = ctypes.create_string_buffer(32)
        salt_buffer = ctypes.create_string_buffer(salt)
        
        self.lib.perform_kem_encapsulation(pk_buffer, ct, ss, salt_buffer, len(salt))
        return ct.raw, ss.raw

    def mutar_datos(self, datos: bytes, secreto: bytes, is_encrypt: bool = True) -> bytes:
        """
        Aplica mutación Vivar usando secreto compartido.
        is_encrypt: True para cifrar, False para descifrar.
        """
        class VivarBuffer(ctypes.Structure):
            _fields_ = [("data", ctypes.c_char_p), ("len", ctypes.c_size_t)]
        
        datos_mutable = ctypes.create_string_buffer(datos)
        buf = VivarBuffer(datos_mutable, len(datos))
        
        # Llamada al motor nativo con flag de cifrado
        res = self.lib.vivar_crypt_engine(
            ctypes.byref(buf), secreto, len(secreto), 1 if is_encrypt else 0
        )
        
        if res != 0:
            raise RuntimeError(f"Error crítico en la mutación Vivar (Código: {res})")
            
        return datos_mutable.raw
