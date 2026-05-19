# Firmas predefinidas añadidas
Se ha ampliado la base inicial de firmas de MalScan para facilitar la demostración.

---
## Criterio de severidad
- 0 a 6: sospechoso
- 7 a 10: malicioso

---
## Firmas sospechosas

| ID | Patrón | Severidad | Tipo |
|---|---|---:|---|
| SIG-001 | powershell -enc | 5 | PowerShell ofuscado |
| SIG-002 | cmd.exe /c | 4 | Ejecución CMD sospechosa |
| SIG-003 | Invoke-WebRequest | 5 | Descarga remota sospechosa |
| SIG-004 | base64_decode | 6 | Decodificación Base64 sospechosa |
| SIG-005 | document.write(unescape( | 6 | JavaScript ofuscado |
| SIG-006 | wget http:// | 5 | Descarga por consola |

---
## Firmas maliciosas

| ID | Patrón | Severidad | Tipo |
|---|---|---:|---|
| SIG-007 | malicious_payload | 9 | Payload malicioso genérico |
| SIG-008 | eval(base64_decode | 9 | Webshell PHP |
| SIG-009 | bash -i >& /dev/tcp/ | 10 | Reverse shell Linux |
| SIG-010 | keylogger_start | 8 | Keylogger simulado |
| SIG-011 | encrypt_all_files | 10 | Ransomware simulado |
| SIG-012 | rm -rf / | 10 | Comando destructivo Linux |

---
## Complejidad
Al aumentar el número de patrones `p`, la búsqueda profunda mantiene la misma forma de complejidad:

```text
O(p · m)
```

donde `m` es el tamaño del archivo.
