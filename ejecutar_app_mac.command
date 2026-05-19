#!/bin/bash

# Ir automáticamente a la carpeta donde está este archivo
cd "$(dirname "$0")"

# Comprobar si existe python3
if ! command -v python3 &> /dev/null
then
    osascript -e 'display dialog "No se ha encontrado python3. Instala Python 3 desde python.org o con Homebrew." buttons {"OK"} default button "OK"'
    exit 1
fi

# Ejecutar MalScan
python3 src/app.py

# Mantener la ventana abierta si hay error
echo ""
echo "Pulsa ENTER para cerrar..."
read
