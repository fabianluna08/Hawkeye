# Mictlan Secure Sandbox Pipeline 💀🛡️

Este proyecto implementa **Mictlan**, un entorno de análisis de malware híbrido (estático y dinámico) diseñado para ejecutar de forma segura cargas de trabajo sospechosas (payloads) en sistemas Linux. La arquitectura combina el aislamiento de microVMs mediante **Firecracker** y la supervisión en tiempo real del kernel del host mediante **eBPF (Extended Berkeley Packet Filter)**.

---

## 🏗️ Arquitectura del Sistema

El pipeline de análisis consta de tres fases secuenciales y concurrentes:
1. **Análisis Estático (YARA)**: Clasifica y filtra el tipo de archivo y detecta firmas maliciosas conocidas antes de la ejecución.
2. **Aislamiento Dinámico (Firecracker MicroVM)**: Ejecuta el binario en una microVM ligera y efímera con red aislada (air-gap) y un sistema de archivos COW (Copy-on-Write) desechable.
3. **Monitoreo de Escape (eBPF/BCC)**: Monitorea el kernel del host para interceptar intentos de escape del sandbox a través de llamadas de ejecución de procesos (`execve`).

### Diagrama de Flujo y Seguridad

```mermaid
graph TD
    A[Payload Sospechoso] --> B[orchestrator.py]
    B --> C[Análisis Estático: static_analysis.py]
    C --> D{¿Escaneo YARA?}
    D -- "Signatura Maliciosa" --> E[Alerta de Malware Estático]
    D -- "Limpio / Informativo" --> F{¿Tipo de Archivo?}
    
    F -- "Windows Executable (.exe)" --> G[Alerta: Omitir Dinámico <br> (No compatible nativamente)]
    F -- "Linux ELF / Script Bash" --> H[Cuarentena Dinámica]
    
    subgraph Host OS (Espacio del Kernel)
        J[Monitor eBPF: monitor.py / sandbox_monitor.c] --> K{syscall: sys_enter_execve}
        K -- "¿Proceso 'fire*' ejecutó host binary?" --> L[ALERTA: Sandbox Escape Attempt Detected]
    end
    
    H --> I[Firecracker MicroVM]
    I --> M[Template Rootfs ext4]
    I --> N[Virtual Air-Gap <br> Sin interfaces de red]
    I --> O[COW Desechable <br> rootfs_*.ext4]
    
    I -. "Ejecución de Carga" .-> P[Llamadas al sistema del host]
    P -.-> J
```

---

## 📁 Estructura del Proyecto

*   [orchestrator.py](file:///home/fabianluna/sandbox/orchestrator.py): El orquestador principal. Valida el archivo, corre el análisis estático y provisiona/destruye la microVM de Firecracker.
*   [static_analysis.py](file:///home/fabianluna/sandbox/static_analysis.py): Analizador estático que compila y ejecuta las reglas YARA.
*   [rules/malware.yar](file:///home/fabianluna/sandbox/rules/malware.yar): Reglas YARA para identificar tipos de archivos (ELF, Windows EXE, scripts, imágenes) y firmas sospechosas comunes (por ejemplo, `rm -rf /`, `/etc/shadow`, shell de netcat, EICAR).
*   [monitor.py](file:///home/fabianluna/sandbox/monitor.py): Script de control de eBPF que compila el código C del monitor, abre un buffer de rendimiento (`perf_buffer`) y reporta alarmas de escape en caliente.
*   [bpf/sandbox_monitor.c](file:///home/fabianluna/sandbox/bpf/sandbox_monitor.c): Programa eBPF escrito en C que se engancha en la sonda `sys_enter_execve` para interceptar si procesos con prefijo `fire*` (Firecracker) intentan generar subprocesos en el sistema host.
*   [setup_firecracker.sh](file:///home/fabianluna/sandbox/setup_firecracker.sh): Script de automatización de entorno. Descarga el binario de Firecracker, un kernel de Linux precompilado (`vmlinux.bin`) y un sistema de archivos base (`rootfs.ext4`).

---

## 🛠️ Pilares Arquitectónicos

### 1. Análisis Estático (YARA)
Antes de permitir la ejecución de cualquier código, el archivo es analizado mediante reglas YARA ([static_analysis.py](file:///home/fabianluna/sandbox/static_analysis.py)). Esto permite:
*   Identificar malware conocido mediante firmas (cadenas como `rm -rf /`, `nc -e /bin/bash`, etc.).
*   Clasificación de formato. Por ejemplo, si se sube un ejecutable de Windows (.exe), el sistema detecta que el kernel Alpine Linux de la microVM no podrá ejecutarlo nativamente y evita levantar el sandbox de forma innecesaria.

### 2. Aislamiento Físico y de Datos (Firecracker MicroVM)
Si el archivo es ejecutable en Linux, [orchestrator.py](file:///home/fabianluna/sandbox/orchestrator.py) inicia una microVM aislada:
*   **Copy-on-Write (COW) Desechable**: Se realiza una copia temporal basada en UUID del sistema de archivos base (`rootfs_<uuid>.ext4`). Todo cambio realizado por el malware se escribe sobre este archivo efímero. Al finalizar la ejecución, el archivo se elimina por completo, garantizando que el host permanezca limpio.
*   **Virtual Air-Gap**: La microVM se configura explícitamente sin interfaces de red. El malware no puede realizar exfiltración de datos, conectarse a servidores de comando y control (C2) ni propagarse por la red local.

### 3. Seguro de Vida del Host (eBPF Escape Monitoring)
Las vulnerabilidades del hipervisor (como escapes de KVM/Firecracker) son raras pero críticas. Para mitigar este riesgo, se utiliza monitoreo de bajo nivel en el kernel del host:
*   El monitor eBPF ([bpf/sandbox_monitor.c](file:///home/fabianluna/sandbox/bpf/sandbox_monitor.c)) intercepta la llamada al sistema `execve` a nivel del kernel de Linux.
*   Dado que Firecracker está diseñado para ejecutar código invitado de manera interna y controlada, el binario del hipervisor en el host (`firecracker`) **nunca** debería realizar llamadas a `execve` para generar nuevos procesos en el sistema operativo del host.
*   Si se detecta un proceso de host que empiece por `fire` invocando `execve`, el monitor eBPF captura los detalles (PID, binario llamado) y envía una alerta de escape inmediata al monitor del host en tiempo real.

---

## 🚀 Requisitos del Sistema y Preparación

### Requisitos previos
*   Sistema operativo Linux (se requiere soporte KVM, usualmente `/dev/kvm` debe estar accesible).
*   Herramientas de compilación de eBPF instaladas (`bcc` y cabeceras del kernel correspondientes).
*   Privilegios de superusuario (`sudo`/`root`) necesarios para interactuar con eBPF y KVM.

### Paso 1: Configurar el Entorno
Descarga los componentes necesarios (Kernel de Linux, RootFS de Alpine/Ubuntu y el binario oficial de Firecracker):
```bash
./setup_firecracker.sh
```

---

## 💻 Instrucciones de Uso

### 1. Activar el Seguro de Vida (Monitor eBPF)
En una terminal secundaria (con privilegios de superusuario), ejecuta el monitor para vigilar el comportamiento del kernel del host:
```bash
sudo python3 monitor.py
```
*Este monitor se quedará escuchando en segundo plano y reportará cualquier intento sospechoso.*

### 2. Ejecutar el Pipeline de Análisis
En tu terminal principal, corre el orquestador apuntando al archivo que deseas analizar:
```bash
python3 orchestrator.py <ruta_al_payload>
```

#### Ejemplos de Pruebas:
*   **Ejecución de un script común**:
    ```bash
    python3 orchestrator.py mock_malware.sh
    ```
*   **Prueba con binario de Windows (Análisis Estático detecta e interrumpe la fase dinámica)**:
    ```bash
    python3 orchestrator.py mock_windows.exe
    ```

---

## 🚀 Capacidades avanzadas (Mejoras)

### A. Captura L7 → detonación automática (`l7_capture/watcher.py`)
Convierte el sandbox de on-demand a **servicio**. Reensambla streams TCP de
puertos de interés (80/443/8080/21/25/587), carva archivos completos, los
clasifica por magic bytes **reusando las reglas YARA `rule_type="info"` y
`scan_file()`** (se agregaron reglas PDF/DOC-OLE/OOXML/RTF), y si el tipo es
interesante (PDF/DOC/DOCX/RTF/EXE/ELF/script) los dispara contra
`orchestrator.py`. Cada resultado se anexa como línea JSON a
`sandbox_reports.jsonl` (raíz de esta carpeta).

*   **Librería elegida: `dpkt`** (pure-python, parsea pcaps sin root, liviano y
    embebible como servicio) frente a `scapy` (más pesado) y al framework
    `file_analysis` de **Zeek** (más robusto para extracción pero no instalado,
    pesado y requiere servicio aparte — sobredimensionado aquí).
*   **Correlación** con `/home/fabianluna/ddos-guardian/alerts.jsonl` (SOLO
    LECTURA): las IPs ya marcadas sospechosas se anotan (`flagged_by_ddos_guardian`).
*   Entradas sin root: pcaps en `l7_capture/pcap_in/` (modo `--watch`) o por CLI.
    Captura viva (`--live IFACE`) requiere root/CAP_NET_RAW.
*   **Fuera de alcance (documentado):** enganche al dashboard de HawkEye. La
    salida vive en `sandbox_reports.jsonl` para conectarse después.

```bash
./venv/bin/python l7_capture/watcher.py captura.pcap        # one-shot
./venv/bin/python l7_capture/watcher.py --watch             # servicio (pcap_in/)
./venv/bin/python l7_capture/watcher.py --file sospechoso.pdf  # archivo suelto
```

### B. Detonación de `.exe` con Wine + Xvfb (Mejora 2)
La rama `is_exe` de `orchestrator.py` ya **no se rinde**: levanta la microVM
(mismo flujo COW efímero + air-gap + monitoreo eBPF) e inyecta el payload, que
un runner de autostart (`guest_assets/detonate.sh`) ejecuta con
`Xvfb + wine <payload>`. Documentos (PDF/DOC/…) se abren con la **app señuelo
vulnerable** (Mejora 3). El air-gap NO se debilita: sigue sin red y el disco COW
se destruye al final.

*   **Concurrencia:** semáforo cross-process (`vm_concurrency.py`, `flock`) limita
    las VMs Firecracker simultáneas. Default `SANDBOX_MAX_VMS=3` (cada VM usa
    512MB; ~1.5GB de 11GB). Configurable por env.
*   **`cp --reflink=always`** reemplaza a `shutil.copy2` para el COW (btrfs).
*   **Telemetría sin red:** el guest escribe `/root/sandbox_telemetry/`
    (exit code, crash/segfault, procesos, archivos escritos, dmesg) y **tras el
    apagado, antes de destruir el COW**, el host la extrae con `debugfs` en modo
    solo-lectura offline (más el `serial_console.log`). Decisión: `debugfs` es la
    vía más simple y confiable sin root (no requiere `losetup`/`mount` ni vsock).

### C. App señuelo vulnerable + entorno "habitado" (Mejora 3, anti-evasión)
La imagen del guest incluye un **visor PDF vulnerable** (`xpdf` por defecto,
histórico por CVEs de corrupción de memoria al parsear PDFs malformados: p.ej.
**CVE-2019-13288** recursión no controlada en `XRef::fetch`, **CVE-2018-16369**
stack overflow, familia CVE-2010-3702). Cuando llega un documento sospechoso se
abre automáticamente con esa app al bootear, dándole a un exploit embebido un
blanco real. Además, cada COW se puebla con **documentos señuelo, historial de
bash y "archivos recientes" falsos** para que el sandbox luzca como un sistema
real habitado (anti-evasión). Todo estrictamente confinado al guest air-gapped,
COW efímero, monitoreado por eBPF — **sin red bajo ningún motivo**.

### Construcción de la imagen base con Wine/Xvfb/señuelo (`setup_rootfs_wine.sh`)
Como no hay sudo sin contraseña ni se puede montar `rootfs.ext4`, se aprovisiona
booteando la microVM **una vez con red temporal** para correr `apt`, y el rootfs
resultante queda como imagen base inmutable. El script tiene 3 fases:
*   **FASE 1 (sin root):** agranda el rootfs (`resize2fs`) e inyecta el
    provisioner de first-boot vía `debugfs`. Se ejecuta sola.
*   **FASE 2 (REQUIERE root):** crea `tap` + NAT y bootea con red para el
    `apt install wine xvfb xpdf`. **Este es el único paso que necesita
    intervención humana.** Comando exacto:
    ```bash
    sudo /home/fabianluna/sandbox/setup_rootfs_wine.sh
    ```
*   **FASE 3 (sin root):** verifica `/root/.provisioned`, quita el unit de
    provisioning y promueve la imagen a base (backup `rootfs.ext4.pre-wine.bak`).

Hasta que se corra la FASE 2, la detonación de `.exe`/documentos funciona
end-to-end pero el runner reporta `tool_missing` (wine/xpdf) en la telemetría en
vez de ejecutarlos — el pipeline entero es validable sin el paso pesado.

### Integración con `agent.py` (proyecto hermano, fuera de alcance)
La CLI `orchestrator.py <payload>` y su salida legible **se mantienen
compatibles**. Se añadió un flag **opcional** `--json` (que `agent.py` no usa)
que imprime una línea final `SANDBOX_RESULT_JSON: {...}` para consumidores
programáticos (el watcher). `agent.py` no requiere cambios. **Aviso:** ahora la
rama `.exe` bootea una VM real (~3-5s), y un payload que se cuelgue puede tardar
hasta `SANDBOX_GUEST_TIMEOUT + SANDBOX_BOOT_OVERHEAD + boot` (~57s con los
defaults conservadores); si `agent.py` reduce su `timeout=60`, subilo.

---

## 🛡️ Consideraciones de Seguridad
*   **Aislamiento de Recursos**: Firecracker proporciona una sobrecarga mínima en comparación con las máquinas virtuales tradicionales mientras mantiene el aislamiento de virtualización de hardware a través de KVM.
*   **Efimeridad Total**: No se conservan estados. Cada análisis corre en su propio espacio virtual limpio y desechable.
*   **Visibilidad Out-of-Band**: Al usar eBPF, el malware que corre dentro del sandbox no tiene visibilidad de que está siendo monitoreado por el kernel del host, haciendo extremadamente difícil para el código malicioso evadir o deshabilitar la telemetría de seguridad.
*   **Air-gap en detonación**: La construcción de imagen (con red temporal) está estrictamente separada de la detonación (sin interfaces de red). El payload y su telemetría entran/salen del guest offline vía `debugfs`, nunca por red.
