import os
import sys
import json
import subprocess
import time
import uuid

import guest_runtime
import escape_monitor_ipc
from vm_concurrency import VMSlot, get_max_vms

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# static_analysis.py depende de yara-python, instalado en el venv propio de Mictlan
# (mictlan/requirements.txt), no en el venv principal del proyecto. Si este
# orquestador es invocado con otro interprete (ej. desde api.py, que usa el venv
# principal), sys.executable heredado seria el interprete equivocado y el import
# de yara fallaria en el subproceso.
STATIC_ANALYSIS_PYTHON = os.path.join(SCRIPT_DIR, "venv", "bin", "python3")
FC_BIN = os.path.join(SCRIPT_DIR, "firecracker")
VM_DATA_DIR = os.path.join(SCRIPT_DIR, "vm_data")
KERNEL_PATH = os.path.join(VM_DATA_DIR, "vmlinux.bin")
ROOTFS_PATH = os.path.join(VM_DATA_DIR, "rootfs.ext4")
TELEMETRY_ROOT = os.path.join(SCRIPT_DIR, "telemetry_out")

# Tiempo (s) que el guest tiene para ejecutar el payload adentro (task.timeout),
# y overhead extra de boot/shutdown que el host espera antes de forzar el kill.
# Nota: agent.py (proyecto hermano, fuera de alcance) invoca este orquestador
# con subprocess timeout=60s. Los defaults se mantienen conservadores para que
# incluso un payload que se cuelgue no exceda ese limite (guest_timeout +
# boot_overhead + ~12s de boot ~= 57s). Ajustables por env para uso via watcher
# (que usa timeout mas holgado) o corridas manuales.
DEFAULT_GUEST_TIMEOUT = int(os.environ.get("SANDBOX_GUEST_TIMEOUT", "30"))
BOOT_OVERHEAD = int(os.environ.get("SANDBOX_BOOT_OVERHEAD", "15"))


def static_analysis(file_path):
    """Corre el analisis estatico YARA. Devuelve (is_clean, mode).

    mode determina como se detona dinamicamente:
      "wine"     -> ejecutable de Windows (.exe) via Wine + Xvfb
      "document" -> PDF/DOC/DOCX/RTF: se abre con la app senuelo vulnerable
      "linux"    -> ELF / script / desconocido: se ejecuta directo en el guest
    """
    print("[*] Running YARA static analysis...")
    result = subprocess.run(
        [STATIC_ANALYSIS_PYTHON, os.path.join(SCRIPT_DIR, "static_analysis.py"), file_path],
        capture_output=True, text=True,
    )
    try:
        report = json.loads(result.stdout)
        types = report.get("detected_file_types", [])
        mode = "linux"
        if types:
            print(f"[*] MAGIC DETECTED: Formato(s) detectado(s): {', '.join(types)}")
            if any("Windows" in t for t in types):
                mode = "wine"
            elif any("Document" in t or "OOXML" in t for t in types):
                mode = "document"
        else:
            print("[*] MAGIC DETECTED: Formato de archivo desconocido.")

        if report.get("status") == "malicious":
            print(f"[!] STATIC ANALYSIS ALERT: Malware signatures found: {report.get('malware_matches')}")
            return (False, mode)
        elif report.get("status") == "clean":
            print("[+] STATIC ANALYSIS PASSED: No malware signatures detected.")
            return (True, mode)
        else:
            print(f"[-] Static analysis error: {report.get('error')}")
            return (False, mode)
    except Exception as e:
        print(f"[-] Error parsing analysis result: {e}")
        return (False, "linux")


def _reflink_copy(src, dst):
    """Copia COW instantanea via `cp --reflink=always` (filesystem btrfs).

    Mucho mas barata que shutil.copy2 (no duplica los 300MB fisicamente, solo
    comparte extents con copy-on-write real del filesystem). Fallback a copia
    normal si por algun motivo reflink no esta disponible.
    """
    r = subprocess.run(["cp", "--reflink=always", src, dst],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[-] reflink fallo ({r.stderr.strip()}); usando copia normal.")
        import shutil
        shutil.copy2(src, dst)


def provision_microvm(file_path, mode="linux", guest_timeout=DEFAULT_GUEST_TIMEOUT):
    """Detona el payload en una microVM Firecracker efimera y air-gapped.

    Flujo: reserva slot de concurrencia -> COW reflink -> inyecta payload +
    autostart + senuelos (offline, sin red) -> boot -> el guest ejecuta y apaga
    -> se extrae telemetria del COW (debugfs, offline) -> se destruye el COW.
    Devuelve un dict con el resultado de la detonacion.
    """
    result = {
        "mode": mode,
        "payload": os.path.basename(file_path),
        "booted": False,
        "telemetry": {},
        "telemetry_dir": None,
        "serial_log": None,
        "error": None,
    }

    run_id = uuid.uuid4().hex[:8]
    socket_path = os.path.join(SCRIPT_DIR, f"sandbox_{run_id}.socket")
    config_path = os.path.join(SCRIPT_DIR, f"vm_config_{run_id}.json")
    cow_rootfs = os.path.join(VM_DATA_DIR, f"rootfs_{run_id}.ext4")
    telem_dir = os.path.join(TELEMETRY_ROOT, run_id)
    for p in (socket_path, config_path):
        if os.path.exists(p):
            os.remove(p)

    print(f"[*] Concurrencia: reservando slot de VM (max {get_max_vms()} simultaneas)...")
    slot = VMSlot(timeout=600)
    try:
        slot.acquire()
    except TimeoutError as e:
        result["error"] = str(e)
        print(f"[-] {e}")
        return result
    print(f"[+] Slot de VM #{slot.index} reservado.")

    fc_proc = None
    serial_log_path = os.path.join(telem_dir, "serial_console.log")
    try:
        print(f"[*] Creando sistema de archivos desechable (COW reflink): {os.path.basename(cow_rootfs)}")
        _reflink_copy(ROOTFS_PATH, cow_rootfs)

        print(f"[*] Inyectando payload + autostart + ambiente senuelo (offline, sin red) [modo={mode}]...")
        guest_payload = guest_runtime.prepare_cow(
            cow_rootfs, file_path, mode, timeout=guest_timeout)
        print(f"[+] Payload inyectado en el guest: {guest_payload}")

        config = {
            "boot-source": {
                "kernel_image_path": KERNEL_PATH,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd",
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": cow_rootfs,
                    "is_root_device": True,
                    "is_read_only": False,
                }
            ],
            # SIN clave "network-interfaces": air-gap total. No se agrega red
            # bajo ningun modo (wine/document incluidos).
            "machine-config": {"vcpu_count": 1, "mem_size_mib": 512, "smt": False},
        }
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        print(f"[-] Starting Firecracker on socket {os.path.basename(socket_path)}")
        print("[*] SEGURIDAD: Air-gap virtual activado. La MicroVM NO tiene interfaces de red configuradas.")
        print("[*] SEGURIDAD: eBPF monitoring (monitor.py) es el seguro de vida del host.")

        os.makedirs(telem_dir, exist_ok=True)
        serial_fh = open(serial_log_path, "wb")
        cmd = [FC_BIN, "--api-sock", socket_path, "--config-file", config_path]
        fc_proc = subprocess.Popen(cmd, stdout=serial_fh, stderr=subprocess.STDOUT)
        result["booted"] = True
        print("[+] MicroVM booted. Detonando payload en aislamiento total (air-gap)...")

        # Avisar al monitor eBPF de escape (bpf/sandbox_monitor.c) que este PID
        # es el proceso host de Firecracker, para que vigile execve/execveat
        # suyos y de sus descendientes (ver escape_monitor_ipc.py). Best-effort:
        # si monitor.py no esta corriendo, seguimos detonando igual -- el
        # monitor de escape es defensa en profundidad, no un requisito.
        if escape_monitor_ipc.notify_tainted_pid(fc_proc.pid):
            print(f"[+] Monitor de escape eBPF notificado: PID {fc_proc.pid} marcado como Firecracker.")
        else:
            print(f"[!] No se pudo notificar al monitor de escape (¿monitor.py no esta corriendo?). "
                  f"La deteccion de fugas para PID {fc_proc.pid} no estara activa esta corrida.")

        # El guest ejecuta detonate.sh y hace poweroff -> Firecracker sale.
        deadline = time.time() + guest_timeout + BOOT_OVERHEAD
        while time.time() < deadline:
            if fc_proc.poll() is not None:
                print("[+] El guest apago la VM (detonacion completa).")
                break
            time.sleep(1)
        else:
            print("[!] Timeout de detonacion: forzando teardown de la MicroVM.")

        if fc_proc.poll() is None:
            fc_proc.terminate()
            try:
                fc_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                fc_proc.kill()
                fc_proc.wait()
        try:
            serial_fh.close()
        except Exception:
            pass

        # --- Extraccion de telemetria del COW (offline, post-apagado, sin red) ---
        print("[*] Extrayendo telemetria del disco COW (debugfs, read-only, pre-destruccion)...")
        report, tdir = guest_runtime.extract_telemetry(cow_rootfs, telem_dir)
        result["telemetry"] = report
        result["telemetry_dir"] = tdir
        result["serial_log"] = serial_log_path
        if report:
            print(f"[+] TELEMETRIA: exit_code={report.get('exit_code')} "
                  f"crashed={report.get('crashed')} "
                  f"archivos_escritos={report.get('files_written_count')} "
                  f"tool_missing={report.get('tool_missing') or 'ninguno'}")
        else:
            print("[-] No se recupero report.json del guest (revisa serial_console.log).")

    except Exception as e:
        result["error"] = str(e)
        print(f"[-] Failed to execute MicroVM: {e}")
    finally:
        print(f"[*] Limpiando entorno: Destruyendo COW desechable {os.path.basename(cow_rootfs)}...")
        if fc_proc is not None and fc_proc.poll() is None:
            fc_proc.kill()
        for p in (cow_rootfs, config_path, socket_path):
            if os.path.exists(p):
                os.remove(p)
        slot.release()
        print("[+] Slot de VM liberado.")
    return result


def main():
    json_out = "--json" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(f"Usage: {sys.argv[0]} [--json] <payload_to_sandbox>")
        sys.exit(1)

    payload = args[0]
    if not os.path.exists(payload):
        print(f"[-] Payload file not found: {payload}")
        sys.exit(1)

    print("====================================")
    print("= ANTIGRAVITY SECURE SANDBOX PIPELINE =")
    print("====================================")

    is_clean, mode = static_analysis(payload)

    result = {"static_clean": is_clean, "mode": mode, "detonation": None}

    if mode == "wine":
        print("[*] Ejecutable de Windows (.exe): detonacion dinamica via Wine + Xvfb en la MicroVM (air-gap).")
        result["detonation"] = provision_microvm(payload, mode="wine")
    elif mode == "document":
        print("[*] Documento sospechoso: se abrira con la app senuelo vulnerable dentro de la MicroVM (air-gap).")
        result["detonation"] = provision_microvm(payload, mode="document")
    else:
        print("[*] Pasando archivo a la cuarentena dinamica (MicroVM Linux)...")
        result["detonation"] = provision_microvm(payload, mode="linux")

    print("[+] Pipeline finished.")
    if json_out:
        # Linea final machine-readable para consumidores programaticos
        # (p.ej. l7_capture/watcher.py). No afecta a agent.py que no pasa --json.
        print("SANDBOX_RESULT_JSON: " + json.dumps(result))


if __name__ == "__main__":
    main()
