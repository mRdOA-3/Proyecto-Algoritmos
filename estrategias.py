from __future__ import annotations
from abc import ABC, abstractmethod
from modelo import Archivo, ResultadoEscaneo
from firmas import BaseFirmas


class EstrategiaEscaneo(ABC):
    """Clase abstracta para aplicar polimorfismo en las estrategias."""

    @abstractmethod
    def escanear_archivo(self, archivo: Archivo, ruta: str, base_firmas: BaseFirmas) -> ResultadoEscaneo:
        pass


class EscaneoRapido(EstrategiaEscaneo):
    """Escaneo rápido: calcula hash y lo compara con firmas conocidas."""

    def escanear_archivo(self, archivo: Archivo, ruta: str, base_firmas: BaseFirmas) -> ResultadoEscaneo:
        hash_archivo = archivo.calcular_hash()
        firma = base_firmas.buscar_por_hash(hash_archivo)

        if firma:
            estado = "malicioso" if firma.severidad >= 7 else "sospechoso"
            return ResultadoEscaneo(
                ruta=ruta,
                estado=estado,
                riesgo=firma.severidad,
                firma_detectada=firma.identificador,
                detalle=f"Coincidencia exacta por hash: {firma.tipo}"
            )

        return ResultadoEscaneo(
            ruta=ruta,
            estado="limpio",
            riesgo=0,
            firma_detectada=None,
            detalle="Sin coincidencias por hash"
        )


class EscaneoProfundo(EstrategiaEscaneo):
    """Escaneo profundo: compara hash y busca patrones en el contenido."""

    def escanear_archivo(self, archivo: Archivo, ruta: str, base_firmas: BaseFirmas) -> ResultadoEscaneo:
        hash_archivo = archivo.calcular_hash()
        firma_hash = base_firmas.buscar_por_hash(hash_archivo)

        if firma_hash:
            estado = "malicioso" if firma_hash.severidad >= 7 else "sospechoso"
            return ResultadoEscaneo(
                ruta=ruta,
                estado=estado,
                riesgo=firma_hash.severidad,
                firma_detectada=firma_hash.identificador,
                detalle=f"Coincidencia exacta por hash: {firma_hash.tipo}"
            )

        firma_patron = base_firmas.buscar_patron_en_contenido(archivo.contenido)

        if firma_patron:
            estado = "malicioso" if firma_patron.severidad >= 7 else "sospechoso"
            return ResultadoEscaneo(
                ruta=ruta,
                estado=estado,
                riesgo=firma_patron.severidad,
                firma_detectada=firma_patron.identificador,
                detalle=f"Patrón detectado: {firma_patron.tipo}"
            )

        return ResultadoEscaneo(
            ruta=ruta,
            estado="limpio",
            riesgo=0,
            firma_detectada=None,
            detalle="Sin coincidencias por hash ni patrones"
        )
