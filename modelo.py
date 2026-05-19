from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
import hashlib


@dataclass
class NodoSistema:
    """Clase base para cualquier elemento del sistema de archivos simulado."""
    nombre: str

    def obtener_ruta(self, ruta_padre: str = "") -> str:
        if ruta_padre:
            return f"{ruta_padre}/{self.nombre}"
        return self.nombre


@dataclass
class Archivo(NodoSistema):
    """Representa un archivo con contenido textual simulado."""
    contenido: str
    extension: str = ".txt"

    def calcular_hash(self) -> str:
        """Calcula SHA-256 del contenido del archivo."""
        return hashlib.sha256(self.contenido.encode("utf-8")).hexdigest()

    def tamano(self) -> int:
        return len(self.contenido)


@dataclass
class Carpeta(NodoSistema):
    """Representa una carpeta, que puede contener archivos u otras carpetas."""
    hijos: List[NodoSistema] = field(default_factory=list)

    def agregar_hijo(self, nodo: NodoSistema) -> None:
        self.hijos.append(nodo)


@dataclass
class FirmaMalware:
    """Representa una firma de malware conocida."""
    identificador: str
    patron: str
    tipo: str
    severidad: int
    descripcion: str


@dataclass
class ResultadoEscaneo:
    """Resultado generado tras analizar un archivo."""
    ruta: str
    estado: str
    riesgo: int
    firma_detectada: str | None
    detalle: str
