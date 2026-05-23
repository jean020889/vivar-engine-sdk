import os
import sys

# 1. Obtenemos la ruta absoluta al binario. 
# Como estamos en /sdk/, debemos subir un nivel (..) y entrar en /target/release/
base_path = os.path.dirname(os.path.abspath(__file__))
lib_path = os.path.join(base_path, "../target/release/libcore.so")

print(f"Buscando el motor en: {lib_path}")

from client import VivarSDK

# 2. Inicializamos el SDK
sdk = VivarSDK(lib_path=lib_path)

# ... resto del código de prueba ...

