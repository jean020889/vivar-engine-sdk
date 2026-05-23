import ctypes
import os

class VivarSDK:
    """
    Cliente para interactuar con el Vivar Encryption Engine (Core en Rust).
    Proporciona interfaces para KEM PQC (Kyber768) y mutación de datos.
    """
    def __init__(self, lib_path=None):
        # Si no se provee ruta, busca automáticamente en la carpeta de build estándar
        if lib_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            lib_path = os.path.abspath(os.path.join(base_dir, "../target/release/libcore.so"))
            
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"No se encuentra el binario libcore.so en: {lib_path}")
        
        # Cargar el binario compilado
        self.lib = ctypes.CDLL(lib_path)
        
        # Definir tipos para las funciones del núcleo (FFI)
        self.lib.vivar_operator_engine.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        self.lib.generate_pqc_keys.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.lib.perform_kem_encapsulation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

    def generar_claves(self):
        """Genera un par de claves Kyber768. Devuelve (pk, sk)."""
        pk = ctypes.create_string_buffer(1184)
        sk = ctypes.create_string_buffer(2400)
        self.lib.generate_pqc_keys(pk, sk)
        return pk.raw, sk.raw

    def encapsular(self, pk_bytes):
        """Encapsula una clave pública PQC. Devuelve (ciphertext, shared_secret)."""
        pk_buffer = ctypes.create_string_buffer(pk_bytes, 1184)
        ct = ctypes.create_string_buffer(1088)
        ss = ctypes.create_string_buffer(32)
        self.lib.perform_kem_encapsulation(pk_buffer, ct, ss)
        return ct.raw, ss.raw

    def mutar_datos(self, datos: bytes, secreto: bytes) -> bytes:
        """
        Aplica la mutación Vivar (XOR) utilizando el secreto compartido.
        El secreto compartido es destruido en memoria tras la operación.
        """
        # Estructura que coincide con el VivarBuffer en Rust
        class VivarBuffer(ctypes.Structure):
            _fields_ = [("data", ctypes.c_char_p), ("len", ctypes.c_size_t)]
        
        datos_mutable = ctypes.create_string_buffer(datos)
        buf = VivarBuffer(datos_mutable, len(datos))
        
        # Llamada al motor nativo (secreto de 32 bytes)
        res = self.lib.vivar_operator_engine(ctypes.byref(buf), secreto, 32)
        
        if res != 0:
            raise RuntimeError("Error crítico en la mutación Vivar.")
            
        return datos_mutable.raw

# --- Ejemplo de uso profesional ---
if __name__ == "__main__":
    try:
        sdk = VivarSDK()
        print("SDK inicializado correctamente.")
        
        pk, sk = sdk.generar_claves()
        ct, ss = sdk.encapsular(pk)
        
        mensaje = b"Datos protegidos de Alumetal"
        mutado = sdk.mutar_datos(mensaje, ss)
        
        print(f"Mensaje original: {mensaje}")
        print(f"Mensaje mutado (HEX): {mutado.hex()}")
    except Exception as e:
        print(f"Error en el SDK: {e}")
      
