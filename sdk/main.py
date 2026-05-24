import sys
import os

# Ajustar el path para importar los módulos desde la raíz si es necesario
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vivar_sdk import VivarEngineSDK
from stegano_handler import SteganoHandler

def mostrar_ayuda():
    print("""
    Uso del SDK Vivar:
    python sdk/main.py [cifrar/descifrar] [archivo_fuente] [portador] [clave]
    """)

def main():
    if len(sys.argv) < 5:
        mostrar_ayuda()
        return

    accion, fuente, portador, clave = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    sdk = VivarEngineSDK()

    try:
        if accion == "cifrar":
            with open(fuente, 'rb') as f:
                datos = f.read()
            
            cifrados = sdk.execute_mutation(datos, clave, encrypt=True)
            SteganoHandler.ocultar_en_portador(cifrados, portador)
            print(f"[OK] Archivo {fuente} cifrado y ocultado exitosamente en {portador}")

        elif accion == "descifrar":
            datos_ocultos = SteganoHandler.extraer_de_portador(portador)
            resultado = sdk.execute_mutation(datos_ocultos, clave, encrypt=False)
            
            with open("recuperado_" + os.path.basename(fuente), "wb") as f:
                f.write(resultado)
            print("[OK] Datos extraídos y descifrados correctamente.")

        else:
            mostrar_ayuda()

    except Exception as e:
        print(f"[ERROR] Fallo en la operación: {e}")

if __name__ == "__main__":
    main()
