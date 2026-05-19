from __future__ import annotations
from typing import Dict, Optional
from modelo import FirmaMalware


class BaseFirmas:
    """Base de datos de firmas usando diccionarios/hash maps."""

    def __init__(self) -> None:
        self.firmas_por_hash: Dict[str, FirmaMalware] = {}
        self.firmas_por_patron: Dict[str, FirmaMalware] = {}

    def agregar_firma_hash(self, hash_archivo: str, firma: FirmaMalware) -> None:
        self.firmas_por_hash[hash_archivo] = firma

    def agregar_firma_patron(self, patron: str, firma: FirmaMalware) -> None:
        self.firmas_por_patron[patron] = firma

    def buscar_por_hash(self, hash_archivo: str) -> Optional[FirmaMalware]:
        return self.firmas_por_hash.get(hash_archivo)

    def buscar_patron_en_contenido(self, contenido: str) -> Optional[FirmaMalware]:
        """
        Busca patrones maliciosos en el contenido.
        Si encuentra varios patrones, devuelve la firma con mayor severidad.

        Ejemplo:
        - powershell -enc -> severidad 5 -> sospechoso
        - malicious_payload -> severidad 9 -> malicioso

        Si un archivo contiene ambos, se queda con malicious_payload.
        Peor caso: O(p * m), donde p es el número de patrones
        y m el tamaño del archivo.
        """
        firma_mas_grave = None

        for patron, firma in self.firmas_por_patron.items():
            if patron in contenido:
                if firma_mas_grave is None or firma.severidad > firma_mas_grave.severidad:
                    firma_mas_grave = firma

        return firma_mas_grave

    def cantidad_firmas(self) -> int:
        return len(self.firmas_por_hash) + len(self.firmas_por_patron)

    def obtener_hashes_registrados(self) -> dict:
        return self.firmas_por_hash
