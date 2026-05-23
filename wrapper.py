import ctypes

lib = ctypes.CDLL("/content/vivar-engine-sdk/target/release/libvivar_engine_sdk.so")

# Definimos el tipo de retorno: un puntero a una estructura compleja
lib.generar_llaves_pqc.restype = ctypes.c_void_p

def obtener_llaves():
    ptr = lib.generar_llaves_pqc()
    # Aquí puedes convertir esos punteros a bytes para tu interfaz
    print(f"Llaves generadas con éxito en memoria: {ptr}")
    return ptr

if __name__ == "__main__":
    llaves = obtener_llaves()
    print("El cifrador PQC está listo para la UI.")
  
