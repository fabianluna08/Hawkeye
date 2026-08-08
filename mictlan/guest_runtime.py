"""
guest_runtime.py — Prepara el disco COW de una detonacion y extrae su telemetria.

Ensambla todo lo que necesita el guest ANTES de bootear (todo offline via
debugfs, sin red, sin root):
  1. El payload -> /root/payload/<nombre>
  2. La tarea (modo, timeout, visor) -> /opt/sandbox/task.json
  3. El runner de detonacion -> /opt/sandbox/detonate.sh (+ systemd unit y su
     symlink en multi-user.target.wants para autostart)
  4. Ambiente senuelo "habitado" (anti-evasion): documentos falsos, historial,
     archivos recientes -> para que el sandbox no luzca pelado.

Y despues del apagado extrae /root/sandbox_telemetry/ del COW (tambien via
debugfs) antes de que el orquestador lo destruya.
"""
import json
import os

import guest_inject as gi

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(SCRIPT_DIR, "guest_assets")

GUEST_PAYLOAD_DIR = "/root/payload"
GUEST_TELEMETRY_DIR = "/root/sandbox_telemetry"
GUEST_SANDBOX_DIR = "/opt/sandbox"


def _inject_autostart(cow_path):
    """Inyecta detonate.sh + unit systemd + symlink de autostart."""
    gi.inject_file(
        cow_path, os.path.join(ASSETS_DIR, "detonate.sh"),
        f"{GUEST_SANDBOX_DIR}/detonate.sh", mode=0o755,
    )
    gi.inject_file(
        cow_path, os.path.join(ASSETS_DIR, "detonate.service"),
        "/etc/systemd/system/detonate.service", mode=0o644,
    )
    # symlink de autostart (equivale a `systemctl enable`)
    link = "/etc/systemd/system/multi-user.target.wants/detonate.service"
    gi.mkdir_p(cow_path, "/etc/systemd/system/multi-user.target.wants")
    if not gi.path_exists(cow_path, link):
        import subprocess
        subprocess.run(
            ["debugfs", "-w", "-R",
             f"symlink {link} /etc/systemd/system/detonate.service", cow_path],
            capture_output=True, text=True,
        )


def _inject_decoys(cow_path):
    """Ambiente senuelo anti-evasion: hace que el guest luzca habitado.

    Todo esto es inerte y confinado al guest air-gapped; solo sirve para que un
    malware que busque signos de sandbox (VM pelada, sin documentos, sin
    historial) crea que es una maquina real de un usuario.
    """
    decoys = {
        "/root/Documents/presupuesto_2026.txt":
            "Presupuesto Q1 2026\nMarketing: 45000\nInfra: 22000\nNomina: 130000\n",
        "/root/Documents/notas_reunion.txt":
            "Reunion 2026-06-28: revisar contratos proveedor, VPN corp, backups.\n",
        "/root/Downloads/factura_marzo.txt":
            "Factura #2026-0331 - Servicios Cloud - Total: USD 1.240,00\n",
        "/root/.bash_history":
            "ls -la\ncd Documents\ncat notas_reunion.txt\nssh admin@10.0.0.5\n"
            "sudo apt update\nfirefox &\nexit\n",
        "/root/.config/user-dirs.dirs":
            'XDG_DOCUMENTS_DIR="$HOME/Documents"\nXDG_DOWNLOAD_DIR="$HOME/Downloads"\n',
        "/root/.local/share/recently-used.xbel":
            '<?xml version="1.0" encoding="UTF-8"?>\n<xbel version="1.0">\n'
            '  <bookmark href="file:///root/Documents/presupuesto_2026.txt"/>\n'
            '  <bookmark href="file:///root/Downloads/factura_marzo.txt"/>\n'
            '</xbel>\n',
    }
    for path, content in decoys.items():
        gi.inject_bytes(cow_path, content, path, mode=0o644)


def prepare_cow(cow_path, payload_host_path, mode, timeout=45, viewer="xpdf"):
    """Deja el disco COW listo para detonar. Devuelve la ruta guest del payload."""
    # payload_host_path puede reflejar un nombre de archivo no confiable (ej.
    # el nombre original de una muestra de malware, o pasado a mano por un
    # analista a orchestrator.py) -> sanitizar antes de que forme parte de un
    # guest_path via debugfs.
    payload_name = gi.sanitize_guest_component(os.path.basename(payload_host_path))
    guest_payload = f"{GUEST_PAYLOAD_DIR}/{payload_name}"

    gi.inject_file(cow_path, payload_host_path, guest_payload, mode=0o755)

    task = {
        "mode": mode,
        "payload_guest_path": guest_payload,
        "timeout": int(timeout),
        "viewer": viewer,
    }
    gi.inject_bytes(cow_path, json.dumps(task, indent=2),
                    f"{GUEST_SANDBOX_DIR}/task.json", mode=0o644)

    _inject_autostart(cow_path)
    _inject_decoys(cow_path)
    return guest_payload


def extract_telemetry(cow_path, dest_dir):
    """Extrae /root/sandbox_telemetry/ del COW (post-apagado) a dest_dir.

    Devuelve (report_dict, dest_dir). report_dict = contenido de report.json
    parseado, o {} si no existe (p.ej. el guest no llego a escribirlo).
    """
    os.makedirs(dest_dir, exist_ok=True)
    gi.extract_dir(cow_path, GUEST_TELEMETRY_DIR, dest_dir)

    report = {}
    # rdump crea dest_dir/sandbox_telemetry/report.json
    candidate = os.path.join(dest_dir, "sandbox_telemetry", "report.json")
    if not os.path.exists(candidate):
        candidate = os.path.join(dest_dir, "report.json")
    if os.path.exists(candidate):
        try:
            with open(candidate) as f:
                report = json.load(f)
        except Exception:
            report = {}
    else:
        # fallback: leer directo del disco
        raw = gi.read_file_text(cow_path, f"{GUEST_TELEMETRY_DIR}/report.json", "")
        if raw:
            try:
                report = json.loads(raw)
            except Exception:
                report = {}
    return report, dest_dir
