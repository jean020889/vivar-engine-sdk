import os
import subprocess
import sys

def preparar_entorno():
    print("--- Inicializando Vivar Encryption Engine ---")
    
    # 1. Verificar si Rust está instalado para el core
    try:
        subprocess.run(["rustc", "--version"], check=True, capture_output=True)
    except:
        print("Error: Rust no encontrado. Instálalo en https://rustup.rs/")
        return

    # 2. Compilar el core de Rust (Producción)
    print("Compilando motor core (Rust)...")
    subprocess.run(["cargo", "build", "--release"], cwd="./", check=True)
    
    # 3. Instalar dependencias de Python
    print("Instalando dependencias...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
    
    print("--- Entorno listo para operar ---")

if __name__ == "__main__":
    preparar_entorno()
