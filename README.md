# MalScan
MalScan es un sistema de ciberseguridad desarrollado en Python que simula el funcionamiento de un antivirus basado en firmas. El programa permite analizar archivos añadidos por el usuario para detectar posibles amenazas mediante comparación de hashes y búsqueda de patrones maliciosos en el contenido.

El sistema utiliza programación orientada a objetos, estructuras de datos eficientes y algoritmos recursivos para recorrer y analizar una estructura de directorios simulada. Además, implementa dos estrategias de escaneo:

- **Escaneo rápido**: compara hashes de archivos con una base de datos de firmas conocidas.
- **Escaneo profundo**: además de verificar hashes, analiza el contenido del archivo en busca de patrones sospechosos.

La aplicación cuenta con una interfaz gráfica desarrollada en Tkinter que permite:

- añadir archivos reales desde el ordenador,
- ejecutar análisis de malware,
- visualizar resultados y niveles de riesgo,
- consultar hashes registrados,
- visualizar archivos añadidos y sus hashes,
- añadir nuevas firmas maliciosas dinámicamente.

MalScan ha sido diseñado con una arquitectura modular y extensible, facilitando la incorporación de nuevas técnicas de detección y permitiendo el análisis de complejidad algorítmica del sistema.

---
## Funcionalidades principales

- Interfaz gráfica en Tkinter.
- Añadir archivos reales desde el ordenador.
- Ver archivos añadidos y su hash SHA-256.
- Escaneo rápido por hash.
- Escaneo profundo por hash y patrones.
- Clasificación de archivos: limpio, sospechoso o malicioso.
- Registro automático de hashes maliciosos detectados.
- Visualización de hashes registrados.
- Exportación de informes en `.html`, `.txt` y `.csv`.
- Código modular con POO, polimorfismo y recursividad.

---
## Ejecutar en Windows

```bash
python src/app.py
```

O haz doble clic en:

```text
ejecutar_app.bat
```

### Crear ejecutable en Windows

```bash
pip install pyinstaller
cd src
pyinstaller --onefile --windowed app.py
```

El ejecutable estará en:

```text
src/dist/app.exe
```
---
## Ejecutar en macOS

Desde Terminal:

```bash
python3 src/app.py
```

También puedes usar el lanzador incluido:

```bash
chmod +x ejecutar_app_mac.command
./ejecutar_app_mac.command
```

### Crear aplicación en macOS

Desde macOS:

```bash
pip3 install pyinstaller
cd src
pyinstaller --onefile --windowed --name MalScan app.py
```

El ejecutable aparecerá en:

```text
src/dist/MalScan
```

> Nota: para generar un `.exe` de Windows hay que hacerlo desde Windows. Para generar una app de macOS hay que hacerlo desde macOS.