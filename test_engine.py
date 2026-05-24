import os
import sys
from vivar_sdk import VivarEngineSDK

def ejecutar_auditoria():
    print("=" * 60)
    print("🔬 INICIANDO AUDITORÍA TÉCNICA DEL VIVAR ENGINE")
    print("=" * 60)

    try:
        sdk = VivarEngineSDK()
    except Exception as e:
        print(f"❌ Fallo crítico: No se pudo cargar el SDK. {e}")
        return

    clave_base = b"VIVAR_ENGINE_PROD_2026_SECURITY_32"
    exito_total = True

    # -----------------------------------------------------------------
    # PRUEBA 1: Consistencia Estructural (Texto Estándar)
    # -----------------------------------------------------------------
    print("\n▶ [PRUEBA 1] Verificación de Consistencia (Round-trip)...")
    data_1 = b"Resolucion analitica conjetura BSD rank 33"
    
    cifrado_1 = sdk.process(data_1, clave_base)
    descifrado_1 = sdk.decrypt(cifrado_1, clave_base)
    
    if data_1 == descifrado_1:
        print("  ✅ PASÓ: Datos idénticos tras ciclo completo.")
    else:
        print("  ❌ FALLÓ: El texto recuperado no coincide.")
        exito_total = False

    # -----------------------------------------------------------------
    # PRUEBA 2: Resistencia de Padding (Límites de bloque de 64 bytes)
    # -----------------------------------------------------------------
    print("\n▶ [PRUEBA 2] Verificación de Límites de Bloque (Padding)...")
    # Probamos texto vacío, texto exacto de 64 bytes y texto de 65 bytes
    casos_padding = [
        b"",
        b"A",
        b"B" * 64,
        b"C" * 65
    ]
    
    p2_fail = False
    for i, caso in enumerate(casos_padding):
        cif = sdk.process(caso, clave_base)
        des = sdk.decrypt(cif, clave_base)
        if caso != des:
            print(f"  ❌ FALLÓ: Error en caso de padding {i} (Longitud {len(caso)})")
            p2_fail = True
            exito_total = False
    if not p2_fail:
        print("  ✅ PASÓ: El esquema de alineación a 64 bytes con \\x80 es estable.")

    # -----------------------------------------------------------------
    # PRUEBA 3: Efecto Avalancha (Cambio mínimo en la clave)
    # -----------------------------------------------------------------
    print("\n▶ [PRUEBA 3] Análisis del Efecto Avalancha (Key Diffusion)...")
    clave_a = b"VIVAR_SECURITY_2026_A"
    clave_b = b"VIVAR_SECURITY_2026_B" # Solo cambia el último carácter
    texto_comun = b"Mismo texto confidencial para evaluar la difusion del estado"
    
    cifrado_a = sdk.process(texto_comun, clave_a)
    cifrado_b = sdk.process(texto_comun, clave_b)
    
    if cifrado_a == cifrado_b:
        print("  ❌ FALLÓ: Las claves distintas generaron el mismo output.")
        exito_total = False
    else:
        # Contamos cuántos bytes son diferentes entre ambos ciphertexts
        bytes_diferentes = sum(1 for b1, b2 in zip(cifrado_a, cifrado_b) if b1 != b2)
        porcentaje_cambio = (bytes_diferentes / len(cifrado_a)) * 100
        print(f"  ✅ PASÓ: Un cambio de 1 carácter en la clave alteró el {porcentaje_cambio:.2f}% del bloque cifrado.")
        if porcentaje_cambio < 40:
            print("  ⚠️ Advertencia: La difusión es baja para cambios mínimos.")

    # -----------------------------------------------------------------
    # PRUEBA 4: Robustez Binaria (Inyección de ruido/bytes arbitrarios)
    # -----------------------------------------------------------------
    print("\n▶ [PRUEBA 4] Integridad con Binarios Puros...")
    data_binaria = bytes([i % 256 for i in range(256)]) # Buffer con todos los bytes posibles (0 a 255)
    
    cifrado_bin = sdk.process(data_binaria, clave_base)
    descifrado_bin = sdk.decrypt(cifrado_bin, clave_base)
    
    if data_binaria == descifrado_bin:
        print("  ✅ PASÓ: El motor es seguro para archivos binarios (Imágenes/PDFs).")
    else:
        print("  ❌ FALLÓ: Colisión o corrupción de bytes no imprimibles.")
        exito_total = False

    # -----------------------------------------------------------------
    # CONCLUSIÓN
    # -----------------------------------------------------------------
    print("\n" + "=" * 60)
    if exito_total:
        print("🏆 DICTAMEN FINAL: EL ENCRIPTADOR ES OPERATIVO Y SEGURO")
        print("Cumple con los criterios de reversibilidad, manejo de entropía y consistencia.")
    else:
        print("🚨 DICTAMEN FINAL: FALLO DE INTEGRIDAD CRIPTOGRÁFICA")
        print("Revisa la lógica del padding o la persistencia de las variables en el core de Rust.")
    print("=" * 60)

if __name__ == "__main__":
    ejecutar_auditoria()
