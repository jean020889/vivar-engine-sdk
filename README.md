# Vivar Engine SDK - Sistema y Motor de Cifrado Híbrido v9.9.5
### Blindaje Criptográfico Post-Cuántico y Esteganografía Avanzada para Aplicaciones B2B

Bienvenido al SDK oficial de **Vivar Engine**, un motor criptográfico de alto rendimiento diseñado en una arquitectura híbrida (Rust Core + Python Wrapper). Este componente permite a empresas de desarrollo de software integrar esquemas de protección de datos de grado militar y esteganografía estocástica en ERPs, sistemas contables, plataformas médicas y pasarelas de pago, sin necesidad de programar lógica criptográfica desde cero.

---

## 1. Cualidades Técnicas Principales
* **Núcleo de Estado Mutante Encadenado:** Implementado en Rust con optimizaciones de bajo nivel para mutar bloques de datos dinámicamente mediante operaciones a nivel de bits $\pmod 8$ y XOR.
* **KDF Ultra-Reforzado Post-Cuántico:** Derivación de claves basada en PBKDF2-HMAC-SHA512 con 1,200,000 iteraciones, diseñada para resistir ataques de fuerza bruta acelerados por hardware y algoritmos cuánticos (Grover).
* **Ocultamiento Esteganográfico:** Inyección de archivos confidenciales dentro de estructuras binarias de archivos portadores legítimos, aplicando una capa balanceada de ruido estocástico para neutralizar el análisis forense de entropía.

---

## 2. Requisitos del Entorno
El entorno de ejecución del cliente final o del servidor debe contar con:
* **Python 3.8 o superior** (con librerías estándar: `ctypes`, `hashlib`, `json`, `secrets`).
* **Compilador de Rust (rustc)** instalado en el sistema operativo para el enlace dinámico automático de la librería de núcleo (`.so` / `.dll`).

---

## 3. Guía de Integración Rápida (Ejemplo de Uso)

Integrar el Operador de Vivar en su flujo de software es sumamente sencillo. El hilo principal del SDK automatiza la compilación nativa en nivel de optimización máxima (`opt-level=3`).

### Inicialización y Llamada al Motor

```python
import ipywidgets as widgets
# Asegúrese de incluir el archivo 'vivar_engine.py' en el directorio de su aplicación

# 1. Definir los parámetros en su código de fondo:
master_key = "SU_LLAVE_MAESTRA_DE_ALTA_ENTROPIA"
modo = "PROTECT (Cifrar)" # O "RECOVER (Descifrar)"

# 2. El SDK ejecutará el aislamiento en Rust de forma transparente:
# - En modo PROTECT: Solicitará el archivo sensible y el archivo portador.
# - En modo RECOVER: Extraerá el binario original decodificando los metadatos.
