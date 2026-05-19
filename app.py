import os
import json
import html as html_escape_lib
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from modelo import Archivo, Carpeta, FirmaMalware
from firmas import BaseFirmas
from estrategias import EscaneoRapido, EscaneoProfundo
from motor import MotorEscaneo


# Paleta visual
COLOR_BG = "#0b1020"
COLOR_PANEL = "#111827"
COLOR_PANEL_2 = "#172033"
COLOR_ACCENT = "#00d4ff"
COLOR_TEXT = "#f8fafc"
COLOR_MUTED = "#9ca3af"
COLOR_GREEN = "#22c55e"
COLOR_YELLOW = "#facc15"
COLOR_RED = "#ef4444"
COLOR_BORDER = "#263244"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
ARCHIVOS_JSON = os.path.join(DATA_DIR, "archivos_guardados.json")


def crear_sistema_simulado() -> Carpeta:
    """
    Sistema inicialmente vacío.
    Los archivos se añaden desde la interfaz gráfica.
    """
    return Carpeta("root")


def crear_base_firmas() -> BaseFirmas:
    """
    Crea una base de firmas inicial con patrones sospechosos y maliciosos.
    Las severidades se interpretan así:
    - 0 a 6: sospechoso
    - 7 a 10: malicioso
    """
    base = BaseFirmas()

    # Firmas sospechosas
    base.agregar_firma_patron(
        "powershell -enc",
        FirmaMalware(
            identificador="SIG-001",
            patron="powershell -enc",
            tipo="PowerShell ofuscado",
            severidad=5,
            descripcion="Uso de PowerShell con comando codificado"
        )
    )

    base.agregar_firma_patron(
        "cmd.exe /c",
        FirmaMalware(
            identificador="SIG-002",
            patron="cmd.exe /c",
            tipo="Ejecución CMD sospechosa",
            severidad=4,
            descripcion="Uso de CMD para ejecutar comandos del sistema"
        )
    )

    base.agregar_firma_patron(
        "Invoke-WebRequest",
        FirmaMalware(
            identificador="SIG-003",
            patron="Invoke-WebRequest",
            tipo="Descarga remota sospechosa",
            severidad=5,
            descripcion="Posible descarga de contenido remoto mediante PowerShell"
        )
    )

    base.agregar_firma_patron(
        "base64_decode",
        FirmaMalware(
            identificador="SIG-004",
            patron="base64_decode",
            tipo="Decodificación Base64 sospechosa",
            severidad=6,
            descripcion="Uso de codificación Base64 para ocultar contenido"
        )
    )

    base.agregar_firma_patron(
        "document.write(unescape(",
        FirmaMalware(
            identificador="SIG-005",
            patron="document.write(unescape(",
            tipo="JavaScript ofuscado",
            severidad=6,
            descripcion="Patrón típico de JavaScript ofuscado"
        )
    )

    base.agregar_firma_patron(
        "wget http://",
        FirmaMalware(
            identificador="SIG-006",
            patron="wget http://",
            tipo="Descarga por consola",
            severidad=5,
            descripcion="Descarga remota mediante wget"
        )
    )

    # Firmas maliciosas
    base.agregar_firma_patron(
        "malicious_payload",
        FirmaMalware(
            identificador="SIG-007",
            patron="malicious_payload",
            tipo="Payload malicioso genérico",
            severidad=9,
            descripcion="Cadena de prueba configurada como maliciosa"
        )
    )

    base.agregar_firma_patron(
        "eval(base64_decode",
        FirmaMalware(
            identificador="SIG-008",
            patron="eval(base64_decode",
            tipo="Webshell PHP",
            severidad=9,
            descripcion="Patrón típico de webshell o malware PHP ofuscado"
        )
    )

    base.agregar_firma_patron(
        "bash -i >& /dev/tcp/",
        FirmaMalware(
            identificador="SIG-009",
            patron="bash -i >& /dev/tcp/",
            tipo="Reverse shell Linux",
            severidad=10,
            descripcion="Patrón asociado a una reverse shell"
        )
    )

    base.agregar_firma_patron(
        "keylogger_start",
        FirmaMalware(
            identificador="SIG-010",
            patron="keylogger_start",
            tipo="Keylogger simulado",
            severidad=8,
            descripcion="Indicador educativo de captura de teclado"
        )
    )

    base.agregar_firma_patron(
        "encrypt_all_files",
        FirmaMalware(
            identificador="SIG-011",
            patron="encrypt_all_files",
            tipo="Ransomware simulado",
            severidad=10,
            descripcion="Indicador educativo de cifrado masivo de archivos"
        )
    )

    base.agregar_firma_patron(
        "rm -rf /",
        FirmaMalware(
            identificador="SIG-012",
            patron="rm -rf /",
            tipo="Comando destructivo Linux",
            severidad=10,
            descripcion="Comando potencialmente destructivo para el sistema"
        )
    )

    return base


class MalScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MalScan - Escáner de Malware por Firmas")
        self.root.geometry("1180x720")
        self.root.minsize(1040, 640)

        self.base_firmas = crear_base_firmas()
        self.sistema = crear_sistema_simulado()
        self.resultados = []

        self.cargar_archivos_guardados()

        self.crear_estilos()
        self.crear_interfaz()
        self.actualizar_tarjetas()

    def obtener_o_crear_carpeta_usuario(self):
        """Devuelve la carpeta de archivos del usuario. Si no existe, la crea."""
        for hijo in self.sistema.hijos:
            if isinstance(hijo, Carpeta) and hijo.nombre == "archivos_usuario":
                return hijo

        carpeta = Carpeta("archivos_usuario")
        self.sistema.agregar_hijo(carpeta)
        return carpeta

    def cargar_archivos_guardados(self):
        """Carga los archivos guardados para que no se pierdan al cerrar la app."""
        if not os.path.exists(ARCHIVOS_JSON):
            return

        try:
            with open(ARCHIVOS_JSON, "r", encoding="utf-8") as fichero:
                datos = json.load(fichero)

            carpeta_usuario = self.obtener_o_crear_carpeta_usuario()

            for item in datos:
                nombre = item.get("nombre", "archivo_sin_nombre.txt")
                contenido = item.get("contenido", "")
                extension = item.get("extension", ".txt")
                carpeta_usuario.agregar_hijo(Archivo(nombre, contenido, extension))

        except Exception:
            # Si el archivo de persistencia está dañado, la app arranca vacía.
            self.sistema = crear_sistema_simulado()

    def guardar_archivos(self):
        """Guarda en JSON todos los archivos añadidos por el usuario."""
        os.makedirs(DATA_DIR, exist_ok=True)

        datos = []
        for archivo in self.obtener_archivos_anadidos():
            datos.append({
                "nombre": archivo.nombre,
                "contenido": archivo.contenido,
                "extension": archivo.extension
            })

        with open(ARCHIVOS_JSON, "w", encoding="utf-8") as fichero:
            json.dump(datos, fichero, indent=4, ensure_ascii=False)

    def crear_estilos(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            rowheight=30,
            font=("Segoe UI", 10),
            background="#f8fafc",
            foreground="#111827",
            fieldbackground="#f8fafc",
            bordercolor=COLOR_BORDER,
            borderwidth=0
        )

        style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 10, "bold"),
            background="#dbeafe",
            foreground="#111827",
            relief="flat"
        )

        style.map("Treeview.Heading", background=[("active", "#bfdbfe")])

        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(12, 8),
            background=COLOR_ACCENT,
            foreground="#00131a",
            borderwidth=0
        )

        style.map(
            "Primary.TButton",
            background=[("active", "#38e4ff"), ("pressed", "#06b6d4")]
        )

        style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(12, 8),
            background="#1f2937",
            foreground=COLOR_TEXT,
            borderwidth=0
        )

        style.map(
            "Secondary.TButton",
            background=[("active", "#374151"), ("pressed", "#111827")]
        )

    def crear_interfaz(self):
        self.root.configure(bg=COLOR_BG)

        contenedor = tk.Frame(self.root, bg=COLOR_BG)
        contenedor.pack(fill="both", expand=True, padx=24, pady=20)

        self.crear_header(contenedor)
        self.crear_panel_acciones(contenedor)
        self.crear_tarjetas(contenedor)
        self.crear_tabla(contenedor)
        self.crear_footer(contenedor)

    def crear_header(self, parent):
        header = tk.Frame(parent, bg=COLOR_PANEL, highlightbackground=COLOR_BORDER, highlightthickness=1)
        header.pack(fill="x", pady=(0, 16))

        izquierda = tk.Frame(header, bg=COLOR_PANEL)
        izquierda.pack(side="left", fill="x", expand=True, padx=20, pady=18)

        tk.Label(
            izquierda,
            text="MalScan",
            bg=COLOR_PANEL,
            fg=COLOR_ACCENT,
            font=("Segoe UI", 28, "bold")
        ).pack(anchor="w")

        tk.Label(
            izquierda,
            text="Proyecto Algoritmos 2026 - Gisela Esteve, Emma Rosendo y Nuria Salas",
            bg=COLOR_PANEL,
            fg=COLOR_MUTED,
            font=("Segoe UI", 11)
        ).pack(anchor="w", pady=(4, 0))

        derecha = tk.Frame(header, bg=COLOR_PANEL)
        derecha.pack(side="right", padx=20, pady=18)

        tk.Label(
            derecha,
            text="Estado del motor",
            bg=COLOR_PANEL,
            fg=COLOR_MUTED,
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="e")

        self.label_estado = tk.Label(
            derecha,
            text="LISTO",
            bg="#052e2b",
            fg="#5eead4",
            font=("Segoe UI", 12, "bold"),
            padx=16,
            pady=6
        )
        self.label_estado.pack(anchor="e", pady=(6, 0))

    def crear_panel_acciones(self, parent):
        panel = tk.Frame(parent, bg=COLOR_PANEL_2, highlightbackground=COLOR_BORDER, highlightthickness=1)
        panel.pack(fill="x", pady=(0, 16), ipady=8)

        fila1 = tk.Frame(panel, bg=COLOR_PANEL_2)
        fila1.pack(fill="x", padx=14, pady=(10, 5))

        fila2 = tk.Frame(panel, bg=COLOR_PANEL_2)
        fila2.pack(fill="x", padx=14, pady=(5, 10))

        ttk.Button(fila1, text="Añadir archivo", style="Primary.TButton", command=self.anadir_archivo).pack(side="left", padx=(0, 10))
        ttk.Button(fila1, text="Escaneo rápido", style="Primary.TButton", command=self.ejecutar_escaneo_rapido).pack(side="left", padx=(0, 10))
        ttk.Button(fila1, text="Escaneo profundo", style="Primary.TButton", command=self.ejecutar_escaneo_profundo).pack(side="left", padx=(0, 10))
        ttk.Button(fila1, text="Exportar informe", style="Primary.TButton", command=self.exportar_informe).pack(side="left", padx=(0, 10))

        ttk.Button(fila2, text="Ver archivos", style="Secondary.TButton", command=self.mostrar_archivos).pack(side="left", padx=(0, 10))
        ttk.Button(fila2, text="Eliminar archivo", style="Secondary.TButton", command=self.eliminar_archivo).pack(side="left", padx=(0, 10))
        ttk.Button(fila2, text="Ver hashes", style="Secondary.TButton", command=self.mostrar_hashes).pack(side="left", padx=(0, 10))
        ttk.Button(fila2, text="Ver firmas", style="Secondary.TButton", command=self.mostrar_firmas).pack(side="left", padx=(0, 10))
        ttk.Button(fila2, text="Añadir firma demo", style="Secondary.TButton", command=self.anadir_firma_demo).pack(side="left", padx=(0, 10))
        ttk.Button(fila2, text="Limpiar resultados", style="Secondary.TButton", command=self.limpiar_resultados).pack(side="left", padx=(0, 10))
        ttk.Button(fila2, text="Borrar archivos guardados", style="Secondary.TButton", command=self.borrar_archivos_guardados).pack(side="left", padx=(0, 10))

        self.label_firmas = tk.Label(
            fila2,
            text=f"Firmas cargadas: {self.base_firmas.cantidad_firmas()}",
            bg=COLOR_PANEL_2,
            fg=COLOR_MUTED,
            font=("Segoe UI", 10, "bold")
        )
        self.label_firmas.pack(side="right")

    def crear_tarjeta(self, parent, titulo, valor, color):
        card = tk.Frame(parent, bg=COLOR_PANEL, highlightbackground=COLOR_BORDER, highlightthickness=1)
        card.pack(side="left", fill="x", expand=True, padx=6)

        tk.Label(
            card,
            text=titulo,
            bg=COLOR_PANEL,
            fg=COLOR_MUTED,
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w", padx=16, pady=(12, 0))

        valor_label = tk.Label(
            card,
            text=valor,
            bg=COLOR_PANEL,
            fg=color,
            font=("Segoe UI", 22, "bold")
        )
        valor_label.pack(anchor="w", padx=16, pady=(2, 12))

        return valor_label

    def crear_tarjetas(self, parent):
        panel = tk.Frame(parent, bg=COLOR_BG)
        panel.pack(fill="x", pady=(0, 16))

        self.card_total = self.crear_tarjeta(panel, "ARCHIVOS", "0", COLOR_ACCENT)
        self.card_limpios = self.crear_tarjeta(panel, "LIMPIOS", "0", COLOR_GREEN)
        self.card_sospechosos = self.crear_tarjeta(panel, "SOSPECHOSOS", "0", COLOR_YELLOW)
        self.card_maliciosos = self.crear_tarjeta(panel, "MALICIOSOS", "0", COLOR_RED)

    def crear_tabla(self, parent):
        panel_tabla = tk.Frame(parent, bg=COLOR_PANEL, highlightbackground=COLOR_BORDER, highlightthickness=1)
        panel_tabla.pack(fill="both", expand=True)

        titulo_tabla = tk.Frame(panel_tabla, bg=COLOR_PANEL)
        titulo_tabla.pack(fill="x", padx=14, pady=(12, 6))

        tk.Label(
            titulo_tabla,
            text="Resultados del análisis",
            bg=COLOR_PANEL,
            fg=COLOR_TEXT,
            font=("Segoe UI", 13, "bold")
        ).pack(side="left")

        tk.Label(
            titulo_tabla,
            text="Los colores indican el estado de cada archivo analizado",
            bg=COLOR_PANEL,
            fg=COLOR_MUTED,
            font=("Segoe UI", 9)
        ).pack(side="right")

        tabla_frame = tk.Frame(panel_tabla, bg=COLOR_PANEL)
        tabla_frame.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        columnas = ("ruta", "estado", "riesgo", "firma", "detalle")
        self.tabla = ttk.Treeview(tabla_frame, columns=columnas, show="headings")

        self.tabla.heading("ruta", text="Archivo")
        self.tabla.heading("estado", text="Estado")
        self.tabla.heading("riesgo", text="Riesgo")
        self.tabla.heading("firma", text="Firma")
        self.tabla.heading("detalle", text="Detalle")

        self.tabla.column("ruta", width=270)
        self.tabla.column("estado", width=120, anchor="center")
        self.tabla.column("riesgo", width=80, anchor="center")
        self.tabla.column("firma", width=120, anchor="center")
        self.tabla.column("detalle", width=450)

        scroll_y = ttk.Scrollbar(tabla_frame, orient="vertical", command=self.tabla.yview)
        self.tabla.configure(yscrollcommand=scroll_y.set)

        self.tabla.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")

        self.tabla.tag_configure("limpio", background="#dcfce7")
        self.tabla.tag_configure("sospechoso", background="#fef9c3")
        self.tabla.tag_configure("malicioso", background="#fee2e2")

    def crear_footer(self, parent):
        footer = tk.Frame(parent, bg=COLOR_BG)
        footer.pack(fill="x", pady=(12, 0))

        self.label_resumen = tk.Label(
            footer,
            text="Resumen: todavía no se ha ejecutado ningún escaneo.",
            bg=COLOR_BG,
            fg=COLOR_TEXT,
            font=("Segoe UI", 10, "bold")
        )
        self.label_resumen.pack(anchor="w")

        self.label_explicacion = tk.Label(
            footer,
            text="Escaneo rápido: compara hashes. Escaneo profundo: compara hashes y busca patrones dentro del contenido.",
            bg=COLOR_BG,
            fg=COLOR_MUTED,
            font=("Segoe UI", 9)
        )
        self.label_explicacion.pack(anchor="w", pady=(4, 0))

    def actualizar_tarjetas(self):
        archivos = self.obtener_archivos_anadidos() if hasattr(self, "sistema") else []

        total = len(self.resultados) if self.resultados else len(archivos)
        limpios = sum(1 for r in self.resultados if r.estado == "limpio")
        sospechosos = sum(1 for r in self.resultados if r.estado == "sospechoso")
        maliciosos = sum(1 for r in self.resultados if r.estado == "malicioso")

        self.card_total.config(text=str(total))
        self.card_limpios.config(text=str(limpios))
        self.card_sospechosos.config(text=str(sospechosos))
        self.card_maliciosos.config(text=str(maliciosos))

    def ejecutar_escaneo_rapido(self):
        self.ejecutar_escaneo("Escaneo rápido", EscaneoRapido())

    def ejecutar_escaneo_profundo(self):
        self.ejecutar_escaneo("Escaneo profundo", EscaneoProfundo())

    def obtener_archivos_anadidos(self):
        archivos = []
        for carpeta in self.sistema.hijos:
            if isinstance(carpeta, Carpeta):
                for archivo in carpeta.hijos:
                    if isinstance(archivo, Archivo):
                        archivos.append(archivo)
        return archivos

    def ejecutar_escaneo(self, nombre, estrategia):
        archivos = self.obtener_archivos_anadidos()
        if not archivos:
            messagebox.showwarning("Sin archivos", "Primero añade al menos un archivo para poder escanear.")
            return

        self.limpiar_tabla()
        self.label_estado.config(text="ESCANEANDO", bg="#422006", fg="#fde68a")
        self.root.update_idletasks()

        motor = MotorEscaneo(self.base_firmas, estrategia)
        self.resultados = motor.escanear(self.sistema)

        for resultado in self.resultados:
            firma = resultado.firma_detectada if resultado.firma_detectada else "-"

            if resultado.estado in ["malicioso", "sospechoso"]:
                self.registrar_hash_detectado(resultado)

            self.tabla.insert(
                "",
                "end",
                values=(resultado.ruta, resultado.estado.upper(), resultado.riesgo, firma, resultado.detalle),
                tags=(resultado.estado,)
            )

        self.label_firmas.config(text=f"Firmas cargadas: {self.base_firmas.cantidad_firmas()}")

        resumen = motor.generar_resumen()
        self.label_resumen.config(
            text=(
                f"{nombre} completado | "
                f"Archivos analizados: {resumen['total_archivos']} | "
                f"Limpios: {resumen['limpios']} | "
                f"Sospechosos: {resumen['sospechosos']} | "
                f"Maliciosos: {resumen['maliciosos']}"
            )
        )

        self.label_estado.config(text="FINALIZADO", bg="#052e16", fg="#86efac")
        self.actualizar_tarjetas()

    def registrar_hash_detectado(self, resultado):
        nombre_archivo = resultado.ruta.split("/")[-1]

        for archivo in self.obtener_archivos_anadidos():
            if archivo.nombre == nombre_archivo:
                hash_archivo = archivo.calcular_hash()

                if hash_archivo not in self.base_firmas.obtener_hashes_registrados():
                    nueva_firma = FirmaMalware(
                        identificador=f"AUTO-{len(self.base_firmas.obtener_hashes_registrados()) + 1}",
                        patron=hash_archivo,
                        tipo="Hash añadido automáticamente",
                        severidad=resultado.riesgo,
                        descripcion="Hash generado automáticamente tras detección"
                    )
                    self.base_firmas.agregar_firma_hash(hash_archivo, nueva_firma)
                break

    def anadir_archivo(self):
        ruta = filedialog.askopenfilename(
            title="Seleccionar archivo",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )

        if not ruta:
            return

        try:
            with open(ruta, "r", encoding="utf-8", errors="ignore") as archivo:
                contenido = archivo.read()

            nombre = os.path.basename(ruta)
            extension = os.path.splitext(nombre)[1] or ".txt"

            carpeta_usuario = self.obtener_o_crear_carpeta_usuario()
            carpeta_usuario.agregar_hijo(Archivo(nombre, contenido, extension))
            self.guardar_archivos()

            self.label_estado.config(text="ARCHIVO AÑADIDO", bg="#082f49", fg="#7dd3fc")
            self.label_resumen.config(text=f"Archivo añadido: {nombre}")
            self.actualizar_tarjetas()

            messagebox.showinfo(
                "Archivo añadido",
                f"El archivo '{nombre}' se ha añadido correctamente al sistema."
            )

        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cargar el archivo:\n{e}")

    def anadir_firma_demo(self):
        self.base_firmas.agregar_firma_patron(
            "malicious_payload",
            FirmaMalware(
                identificador="SIG-003",
                patron="malicious_payload",
                tipo="Payload malicioso genérico",
                severidad=7,
                descripcion="Cadena sospechosa usada como payload"
            )
        )

        self.label_firmas.config(text=f"Firmas cargadas: {self.base_firmas.cantidad_firmas()}")
        self.label_estado.config(text="FIRMA AÑADIDA", bg="#082f49", fg="#7dd3fc")
        messagebox.showinfo("Firma añadida", "Se ha añadido la firma demo SIG-003: malicious_payload")


    def eliminar_archivo(self):
        """
        Permite seleccionar y borrar un archivo añadido.
        """
        archivos = self.obtener_archivos_anadidos()

        if not archivos:
            messagebox.showwarning(
                "Sin archivos",
                "No hay archivos guardados para eliminar."
            )
            return

        ventana = tk.Toplevel(self.root)
        ventana.title("Eliminar archivo")
        ventana.geometry("500x420")

        tk.Label(
            ventana,
            text="Selecciona un archivo para eliminar",
            font=("Segoe UI", 15, "bold")
        ).pack(anchor="w", padx=16, pady=(16, 10))

        lista = tk.Listbox(
            ventana,
            font=("Segoe UI", 11),
            activestyle="none"
        )
        lista.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        for archivo in archivos:
            lista.insert("end", archivo.nombre)

        def confirmar_eliminacion():
            seleccion = lista.curselection()

            if not seleccion:
                messagebox.showwarning(
                    "Sin selección",
                    "Selecciona un archivo."
                )
                return

            nombre_archivo = lista.get(seleccion[0])

            confirmar = messagebox.askyesno(
                "Confirmar",
                f"¿Eliminar '{nombre_archivo}'?"
            )

            if not confirmar:
                return

            for carpeta in self.sistema.hijos:
                if isinstance(carpeta, Carpeta):
                    carpeta.hijos = [
                        archivo for archivo in carpeta.hijos
                        if archivo.nombre != nombre_archivo
                    ]

            if hasattr(self, "guardar_archivos"):
                self.guardar_archivos()

            self.actualizar_tarjetas()

            self.label_resumen.config(
                text=f"Archivo eliminado: {nombre_archivo}"
            )

            ventana.destroy()

            messagebox.showinfo(
                "Eliminado",
                f"'{nombre_archivo}' eliminado correctamente."
            )

        ttk.Button(
            ventana,
            text="Eliminar archivo seleccionado",
            command=confirmar_eliminacion
        ).pack(pady=(0, 16))

    def mostrar_archivos(self):
        ventana = tk.Toplevel(self.root)
        ventana.title("Archivos añadidos")
        ventana.geometry("900x460")
        ventana.configure(bg=COLOR_BG)

        tk.Label(
            ventana,
            text="Archivos añadidos",
            bg=COLOR_BG,
            fg=COLOR_ACCENT,
            font=("Segoe UI", 18, "bold")
        ).pack(anchor="w", padx=16, pady=(14, 6))

        tabla = ttk.Treeview(ventana, columns=("nombre", "tamano", "hash"), show="headings")
        tabla.heading("nombre", text="Archivo")
        tabla.heading("tamano", text="Tamaño")
        tabla.heading("hash", text="Hash SHA-256")

        tabla.column("nombre", width=220)
        tabla.column("tamano", width=100, anchor="center")
        tabla.column("hash", width=540)

        scroll = ttk.Scrollbar(ventana, orient="vertical", command=tabla.yview)
        tabla.configure(yscrollcommand=scroll.set)

        tabla.pack(side="left", fill="both", expand=True, padx=(16, 0), pady=10)
        scroll.pack(side="right", fill="y", padx=(0, 16), pady=10)

        archivos = self.obtener_archivos_anadidos()

        if not archivos:
            tabla.insert("", "end", values=("No hay archivos añadidos", "-", "-"))
            return

        for archivo in archivos:
            tabla.insert(
                "",
                "end",
                values=(archivo.nombre, f"{archivo.tamano()} bytes", archivo.calcular_hash())
            )


    def mostrar_firmas(self):
        ventana = tk.Toplevel(self.root)
        ventana.title("Base de firmas")
        ventana.geometry("1000x500")

        tabla = ttk.Treeview(
            ventana,
            columns=("categoria","id","valor","tipo","sev","desc"),
            show="headings"
        )

        tabla.heading("categoria", text="Categoría")
        tabla.heading("id", text="ID")
        tabla.heading("valor", text="Patrón / Hash")
        tabla.heading("tipo", text="Tipo")
        tabla.heading("sev", text="Severidad")
        tabla.heading("desc", text="Descripción")

        tabla.column("categoria", width=100)
        tabla.column("id", width=100)
        tabla.column("valor", width=300)
        tabla.column("tipo", width=200)
        tabla.column("sev", width=100)
        tabla.column("desc", width=300)

        tabla.pack(fill="both", expand=True)

        for patron, firma in self.base_firmas.firmas_por_patron.items():
            tabla.insert(
                "",
                "end",
                values=("PATRÓN", firma.identificador, patron, firma.tipo, firma.severidad, firma.descripcion)
            )

        for h, firma in self.base_firmas.firmas_por_hash.items():
            tabla.insert(
                "",
                "end",
                values=("HASH", firma.identificador, h, firma.tipo, firma.severidad, firma.descripcion)
            )


    def mostrar_hashes(self):
        hashes = self.base_firmas.obtener_hashes_registrados()

        ventana = tk.Toplevel(self.root)
        ventana.title("Lista de hashes verificados")
        ventana.geometry("880x430")
        ventana.configure(bg=COLOR_BG)

        tk.Label(
            ventana,
            text="Hashes verificados",
            bg=COLOR_BG,
            fg=COLOR_ACCENT,
            font=("Segoe UI", 18, "bold")
        ).pack(anchor="w", padx=16, pady=(14, 6))

        texto = tk.Text(ventana, bg=COLOR_PANEL, fg=COLOR_TEXT, insertbackground=COLOR_TEXT, font=("Consolas", 10), wrap="word")
        texto.pack(fill="both", expand=True, padx=16, pady=10)

        if not hashes:
            texto.insert("end", "No hay hashes registrados.\n")
        else:
            for hash_archivo, firma in hashes.items():
                texto.insert(
                    "end",
                    f"ID: {firma.identificador}\n"
                    f"Hash: {hash_archivo}\n"
                    f"Tipo: {firma.tipo}\n"
                    f"Severidad: {firma.severidad}\n"
                    f"Descripción: {firma.descripcion}\n"
                    f"{'-'*90}\n"
                )

        texto.config(state="disabled")

    def exportar_informe(self):
        if not self.resultados:
            messagebox.showwarning(
                "Sin resultados",
                "Primero ejecuta un escaneo antes de exportar el informe."
            )
            return

        ruta_guardado = filedialog.asksaveasfilename(
            title="Guardar informe",
            defaultextension=".html",
            filetypes=[
                ("Informe HTML", "*.html"),
                ("Informe TXT", "*.txt"),
                ("Informe CSV", "*.csv"),
                ("Todos los archivos", "*.*")
            ]
        )

        if not ruta_guardado:
            return

        try:
            extension = os.path.splitext(ruta_guardado)[1].lower()
            fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            total = len(self.resultados)
            limpios = sum(1 for r in self.resultados if r.estado == "limpio")
            sospechosos = sum(1 for r in self.resultados if r.estado == "sospechoso")
            maliciosos = sum(1 for r in self.resultados if r.estado == "malicioso")

            if extension == ".csv":
                with open(ruta_guardado, "w", encoding="utf-8") as informe:
                    informe.write("fecha,ruta,estado,riesgo,firma,detalle\n")

                    for resultado in self.resultados:
                        firma = resultado.firma_detectada if resultado.firma_detectada else "-"
                        detalle = resultado.detalle.replace(",", ";").replace("\n", " ")
                        informe.write(
                            f"{fecha},{resultado.ruta},{resultado.estado},"
                            f"{resultado.riesgo},{firma},{detalle}\n"
                        )

                    informe.write("\n")
                    informe.write(f"total_archivos,{total}\n")
                    informe.write(f"limpios,{limpios}\n")
                    informe.write(f"sospechosos,{sospechosos}\n")
                    informe.write(f"maliciosos,{maliciosos}\n")

            elif extension == ".txt":
                with open(ruta_guardado, "w", encoding="utf-8") as informe:
                    informe.write("INFORME DE ESCANEO - MALSCAN\n")
                    informe.write("=" * 70 + "\n")
                    informe.write(f"Fecha del informe: {fecha}\n")
                    informe.write(f"Archivos analizados: {total}\n")
                    informe.write(f"Limpios: {limpios}\n")
                    informe.write(f"Sospechosos: {sospechosos}\n")
                    informe.write(f"Maliciosos: {maliciosos}\n")
                    informe.write("=" * 70 + "\n\n")

                    informe.write("RESULTADOS DETALLADOS\n")
                    informe.write("-" * 70 + "\n")

                    for resultado in self.resultados:
                        firma = resultado.firma_detectada if resultado.firma_detectada else "-"
                        informe.write(f"Archivo: {resultado.ruta}\n")
                        informe.write(f"Estado: {resultado.estado.upper()}\n")
                        informe.write(f"Riesgo: {resultado.riesgo}\n")
                        informe.write(f"Firma detectada: {firma}\n")
                        informe.write(f"Detalle: {resultado.detalle}\n")
                        informe.write("-" * 70 + "\n")

                    informe.write("\nHASHES REGISTRADOS\n")
                    informe.write("-" * 70 + "\n")

                    hashes = self.base_firmas.obtener_hashes_registrados()
                    if not hashes:
                        informe.write("No hay hashes registrados.\n")
                    else:
                        for hash_archivo, firma in hashes.items():
                            informe.write(f"ID: {firma.identificador}\n")
                            informe.write(f"Hash: {hash_archivo}\n")
                            informe.write(f"Tipo: {firma.tipo}\n")
                            informe.write(f"Severidad: {firma.severidad}\n")
                            informe.write(f"Descripción: {firma.descripcion}\n")
                            informe.write("-" * 70 + "\n")

            else:
                self.exportar_informe_html(
                    ruta_guardado,
                    fecha,
                    total,
                    limpios,
                    sospechosos,
                    maliciosos
                )

            self.label_estado.config(text="INFORME EXPORTADO", bg="#052e16", fg="#86efac")
            messagebox.showinfo(
                "Informe exportado",
                f"El informe se ha guardado correctamente en:\n{ruta_guardado}"
            )

        except Exception as e:
            messagebox.showerror("Error", f"No se pudo exportar el informe:\n{e}")

    def exportar_informe_html(self, ruta_guardado, fecha, total, limpios, sospechosos, maliciosos):
        def limpiar(texto):
            return html_escape_lib.escape(str(texto))

        porcentaje_malicioso = 0 if total == 0 else round((maliciosos / total) * 100, 2)
        porcentaje_sospechoso = 0 if total == 0 else round((sospechosos / total) * 100, 2)
        porcentaje_limpio = 0 if total == 0 else round((limpios / total) * 100, 2)

        filas_resultados = ""
        for resultado in self.resultados:
            firma = resultado.firma_detectada if resultado.firma_detectada else "-"
            estado = resultado.estado.lower()

            if estado == "malicioso":
                badge = "danger"
            elif estado == "sospechoso":
                badge = "warning"
            else:
                badge = "success"

            filas_resultados += f"""
            <tr>
                <td>{limpiar(resultado.ruta)}</td>
                <td><span class="badge {badge}">{limpiar(resultado.estado.upper())}</span></td>
                <td>{limpiar(resultado.riesgo)}</td>
                <td>{limpiar(firma)}</td>
                <td>{limpiar(resultado.detalle)}</td>
            </tr>
            """

        hashes = self.base_firmas.obtener_hashes_registrados()
        filas_hashes = ""

        if not hashes:
            filas_hashes = """
            <tr>
                <td colspan="5" class="muted">No hay hashes registrados.</td>
            </tr>
            """
        else:
            for hash_archivo, firma in hashes.items():
                filas_hashes += f"""
                <tr>
                    <td>{limpiar(firma.identificador)}</td>
                    <td class="hash">{limpiar(hash_archivo)}</td>
                    <td>{limpiar(firma.tipo)}</td>
                    <td>{limpiar(firma.severidad)}</td>
                    <td>{limpiar(firma.descripcion)}</td>
                </tr>
                """

        html_contenido = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe MalScan</title>
    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #0b1020;
            color: #f8fafc;
        }}

        .container {{
            max-width: 1180px;
            margin: 0 auto;
            padding: 32px;
        }}

        .header {{
            background: linear-gradient(135deg, #111827, #172033);
            border: 1px solid #263244;
            border-radius: 18px;
            padding: 28px;
            margin-bottom: 24px;
        }}

        .title {{
            font-size: 34px;
            font-weight: 800;
            color: #00d4ff;
            margin: 0;
        }}

        .subtitle {{
            color: #9ca3af;
            margin-top: 8px;
            font-size: 15px;
        }}

        .meta {{
            margin-top: 18px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}

        .meta span {{
            background: #0f172a;
            border: 1px solid #263244;
            border-radius: 999px;
            padding: 8px 12px;
            color: #d1d5db;
            font-size: 13px;
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}

        .card {{
            background: #111827;
            border: 1px solid #263244;
            border-radius: 16px;
            padding: 18px;
        }}

        .card-title {{
            color: #9ca3af;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
        }}

        .card-value {{
            margin-top: 8px;
            font-size: 32px;
            font-weight: 800;
        }}

        .blue {{ color: #00d4ff; }}
        .green {{ color: #22c55e; }}
        .yellow {{ color: #facc15; }}
        .red {{ color: #ef4444; }}

        .section {{
            background: #111827;
            border: 1px solid #263244;
            border-radius: 16px;
            padding: 22px;
            margin-bottom: 24px;
        }}

        h2 {{
            margin: 0 0 16px;
            color: #f8fafc;
            font-size: 20px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            overflow: hidden;
            border-radius: 12px;
        }}

        th {{
            background: #1f2937;
            color: #dbeafe;
            text-align: left;
            padding: 12px;
            font-size: 13px;
        }}

        td {{
            border-top: 1px solid #263244;
            padding: 12px;
            color: #e5e7eb;
            font-size: 13px;
            vertical-align: top;
        }}

        tr:hover td {{
            background: #172033;
        }}

        .badge {{
            display: inline-block;
            padding: 5px 9px;
            border-radius: 999px;
            font-weight: 800;
            font-size: 11px;
        }}

        .success {{
            background: #052e16;
            color: #86efac;
        }}

        .warning {{
            background: #422006;
            color: #fde68a;
        }}

        .danger {{
            background: #450a0a;
            color: #fecaca;
        }}

        .hash {{
            font-family: Consolas, Monaco, monospace;
            font-size: 12px;
            word-break: break-all;
        }}

        .muted {{
            color: #9ca3af;
        }}

        .progress {{
            height: 12px;
            background: #1f2937;
            border-radius: 999px;
            overflow: hidden;
            margin-top: 8px;
        }}

        .bar {{
            height: 100%;
            float: left;
        }}

        .bar-green {{ background: #22c55e; width: {porcentaje_limpio}%; }}
        .bar-yellow {{ background: #facc15; width: {porcentaje_sospechoso}%; }}
        .bar-red {{ background: #ef4444; width: {porcentaje_malicioso}%; }}

        .footer {{
            color: #9ca3af;
            text-align: center;
            font-size: 12px;
            margin-top: 30px;
        }}

        @media print {{
            body {{
                background: white;
                color: black;
            }}

            .section, .card, .header {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">MalScan Security Report</h1>
            <div class="subtitle">Informe del análisis del malware.</div>
            <div class="meta">
                <span>Fecha: {limpiar(fecha)}</span>
            </div>
        </div>

        <div class="cards">
            <div class="card">
                <div class="card-title">Archivos analizados</div>
                <div class="card-value blue">{total}</div>
            </div>
            <div class="card">
                <div class="card-title">Limpios</div>
                <div class="card-value green">{limpios}</div>
            </div>
            <div class="card">
                <div class="card-title">Sospechosos</div>
                <div class="card-value yellow">{sospechosos}</div>
            </div>
            <div class="card">
                <div class="card-title">Maliciosos</div>
                <div class="card-value red">{maliciosos}</div>
            </div>
        </div>

        <div class="section">
            <h2>Distribución del análisis</h2>
            <div class="progress">
                <div class="bar bar-green"></div>
                <div class="bar bar-yellow"></div>
                <div class="bar bar-red"></div>
            </div>
            <p class="muted">
                Limpios: {porcentaje_limpio}% · Sospechosos: {porcentaje_sospechoso}% · Maliciosos: {porcentaje_malicioso}%
            </p>
        </div>

        <div class="section">
            <h2>Resultados detallados</h2>
            <table>
                <thead>
                    <tr>
                        <th>Archivo</th>
                        <th>Estado</th>
                        <th>Riesgo</th>
                        <th>Firma</th>
                        <th>Detalle</th>
                    </tr>
                </thead>
                <tbody>
                    {filas_resultados}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Hashes registrados</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Hash SHA-256</th>
                        <th>Tipo</th>
                        <th>Severidad</th>
                        <th>Descripción</th>
                    </tr>
                </thead>
                <tbody>
                    {filas_hashes}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Proyecto Algoritmos 2026 - Gisela Esteve, Emma Rosendo y Nuria Salas
        </div>
    </div>
</body>
</html>
"""

        with open(ruta_guardado, "w", encoding="utf-8") as informe:
            informe.write(html_contenido)

    def borrar_archivos_guardados(self):
        confirmar = messagebox.askyesno(
            "Borrar archivos guardados",
            "¿Seguro que quieres borrar todos los archivos añadidos y guardados?"
        )

        if not confirmar:
            return

        self.sistema = crear_sistema_simulado()
        self.resultados = []
        self.limpiar_tabla()

        try:
            if os.path.exists(ARCHIVOS_JSON):
                os.remove(ARCHIVOS_JSON)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo borrar el archivo de persistencia:\n{e}")
            return

        self.label_resumen.config(text="Archivos guardados borrados correctamente.")
        self.label_estado.config(text="ARCHIVOS BORRADOS", bg="#450a0a", fg="#fecaca")
        self.actualizar_tarjetas()

    def limpiar_tabla(self):
        for item in self.tabla.get_children():
            self.tabla.delete(item)

    def limpiar_resultados(self):
        self.limpiar_tabla()
        self.resultados = []
        self.label_resumen.config(text="Resumen: resultados limpiados.")
        self.label_estado.config(text="LISTO", bg="#052e2b", fg="#5eead4")
        self.actualizar_tarjetas()


if __name__ == "__main__":
    root = tk.Tk()
    app = MalScanApp(root)
    root.mainloop()
