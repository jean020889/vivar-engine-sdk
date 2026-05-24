import ctypes
import os

class VivarBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]

class VivarEngineSDK:
    def __init__(self, lib_path: str = "/content/vivar-engine-sdk/target/release/libvivar_engine.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"El núcleo industrial no fue localizado en: {lib_path}")
            
        self._core = ctypes.CDLL(lib_path)
        self._core.vivar_operator_engine.argtypes = [
            ctypes.POINTER(VivarBuffer), 
            ctypes.POINTER(ctypes.c_uint8), 
            ctypes.c_size_t
        ]
        self._core.vivar_operator_engine.restype = ctypes.c_int

    def process(self, data: bytes, key: bytes) -> bytes:
        # Aseguramos que trabajamos con copias mutables independientes
        mutable_data = bytearray(data)
        key_data = bytearray(key)
        data_len = len(mutable_data)
        
        # Creamos los arreglos de C explícitos
        c_data = (ctypes.c_uint8 * data_len).from_buffer(mutable_data)
        c_key = (ctypes.c_uint8 * len(key_data)).from_buffer(key_data)
        
        # Creamos la estructura buffer pasando el puntero directo al array de C
        buf = VivarBuffer(data=ctypes.cast(c_data, ctypes.POINTER(ctypes.c_uint8)), len=data_len)
        
        # Invocación al núcleo industrial
        status = self._core.vivar_operator_engine(ctypes.byref(buf), c_key, len(key_data))
        
        if status != 0:
            raise RuntimeError(f"Falla crítica en la mutación industrial. Código: {status}")
            
        return bytes(mutable_data)

# --- Verificación de integridad ---
if __name__ == "__main__":
    try:
        sdk = VivarEngineSDK()
        datos = b"Prueba de integridad absoluta 2026"
        llave = b"KEY_INDUSTRIAL_VIVAR"
        
        cifrado = sdk.process(datos, llave)
        recuperado = sdk.process(cifrado, llave)
        
        print(f"Original:   {datos}")
        print(f"Recuperado: {recuperado}")
        
        assert datos == recuperado, "❌ ERROR: Los datos no coinciden tras el descifrado."
        print("✅ ÉXITO: Involución verificada correctamente.")
        
    except Exception as e:
        print(f"Error: {e}")
