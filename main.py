from app import crear_sistema_simulado, crear_base_firmas
from estrategias import EscaneoRapido, EscaneoProfundo
from motor import MotorEscaneo


def ejecutar_demo(nombre_estrategia, estrategia):
    print(f"\n=== {nombre_estrategia} ===")

    sistema = crear_sistema_simulado()
    base = crear_base_firmas()
    motor = MotorEscaneo(base, estrategia)

    resultados = motor.escanear(sistema)

    for resultado in resultados:
        print(
            f"[{resultado.estado.upper()}] {resultado.ruta} | "
            f"Riesgo: {resultado.riesgo} | {resultado.detalle}"
        )

    print("\nResumen:", motor.generar_resumen())


if __name__ == "__main__":
    ejecutar_demo("Escaneo rápido", EscaneoRapido())
    ejecutar_demo("Escaneo profundo", EscaneoProfundo())
