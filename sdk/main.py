import sys
import os
import getpass

# Ajustar el path para importar los módulos desde la raíz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vivar_sdk import VivarEngineSDK
from stegano_handler import SteganoHandler

def mostrar_ayuda():
    print("""
    ==================================================
    Vivar Encryption Engine SDK - CLI Manager
    ==================================================
    Uso: python main.py [cifrar/descifrar] [archivo_fuente] [portador]
    
    Nota: La clave será solicitada de forma segura.
    """)

def main():
    if len(sys.argv) < 4:
        mostrar_ayuda()
        return

    accion = sys.argv[1].lower()
    fuente = sys.argv[2]
    portador = sys.argv[3]

    # Validación de archivos
    if not os.path.exists(fuente) or not os.path.exists(portador):
        print("[ERROR] Archivo fuente o portador no encontrado.")
        return

    # Entrada de clave segura (no se muestra en consola ni en historial)
    clave = getpass.getpass("Ingrese clave maestra: ")
    
    sdk = VivarEngineSDK()

    try:
        if accion == "cifrar":
            with open(fuente, 'rb') as f:
                datos = f.read()
            
            # Mutación criptográfica
            cifrados = sdk.execute_mutation(datos, clave, encrypt=True)
            # Ocultamiento esteganográfico en el portador
            SteganoHandler.ocultar_en_portador(cifrados, portador)
            print(f"\n[OK] Datos cifrados y ocultados exitosamente en: {portador}")

        elif accion == "descifrar":
            # Extracción del portador
            datos_ocultos = SteganoHandler.extraer_de_portador(portador)
            # Descifrado y recuperación
            resultado = sdk.execute_mutation(datos_ocultos, clave, encrypt=False)
            
            nombre_salida = "recuperado_" + os.path.basename(fuente)
            with open(nombre_salida, "wb") as f:
                f.write(resultado)
            print(f"\n[OK] Datos extraídos y guardados en: {nombre_salida}")

        else:
            mostrar_ayuda()

    except Exception as e:
        print(f"\n[ERROR] Fallo en la operación crítica: {e}")
    
    # Limpieza de variable de clave en memoria
    del clave

if __name__ == "__main__":
    main()
