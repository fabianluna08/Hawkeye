#!/usr/bin/env python3
"""
l7_capture/watcher.py — Captura L7 -> detonacion automatica en el sandbox.

Convierte el sandbox de 100% on-demand a un servicio que reensambla trafico,
carva archivos completos de los streams TCP, identifica su tipo por magic bytes
(reutilizando las reglas YARA rule_type="info" y scan_file() del proyecto) y, si
el tipo es interesante (PDF/DOC/DOCX/RTF/EXE/ELF/script), lo dispara contra el
pipeline existente (orchestrator.py). Cada resultado se escribe como una linea
JSON en /home/fabianluna/sandbox/sandbox_reports.jsonl.

Eleccion de libreria de reensamblado — dpkt (vs scapy vs Zeek)
--------------------------------------------------------------
Se eligio **dpkt**:
  * Pure-python, sin dependencias nativas ni servicios aparte -> se embebe como
    servicio Python trivialmente (el requisito del enunciado).
  * Parsea pcaps SIN root (a diferencia de la captura viva, que necesita
    CAP_NET_RAW). Encaja con el entorno sin sudo de esta maquina.
  * Mucho mas liviano/rapido que scapy para parseo masivo de paquetes.
  * Zeek (framework file_analysis) es mas robusto para extraccion de archivos,
    pero NO esta instalado, es pesado y requiere infra/servicio aparte:
    sobredimensionado para embeber en este microservicio.
dpkt no trae reensamblado "de fabrica", asi que se implementa un reensamblado
minimo por-flujo ordenando segmentos por numero de secuencia (suficiente y
estandar; el trabajo pesado de parseo de paquetes/HTTP si lo hace dpkt).

Entradas soportadas (sin root):
  * Archivos .pcap/.pcapng colocados en l7_capture/pcap_in/ (modo --watch), o
    pasados por CLI. Es la via practica sin privilegios.
  * (Opcional) captura viva con --live IFACE, que SI requiere root/CAP_NET_RAW.
  * Correlacion con /home/fabianluna/ddos-guardian/alerts.jsonl (SOLO LECTURA):
    las IPs ya marcadas sospechosas se anotan en el reporte y elevan prioridad.

NOTA: enganchar esto al dashboard de HawkEye queda FUERA DE ALCANCE. La salida
queda en sandbox_reports.jsonl para que se conecte despues.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

import dpkt

# Permitir importar static_analysis del directorio padre
SANDBOX_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SANDBOX_DIR)
import static_analysis  # noqa: E402

ORCHESTRATOR = os.path.join(SANDBOX_DIR, "orchestrator.py")
CAPTURED_DIR = os.path.join(SANDBOX_DIR, "captured_payloads")
REPORTS_FILE = os.path.join(SANDBOX_DIR, "sandbox_reports.jsonl")
PCAP_IN = os.path.join(SANDBOX_DIR, "l7_capture", "pcap_in")
_parent_alerts = os.path.join(os.path.dirname(SANDBOX_DIR), "alerts.jsonl")
ALERTS_JSONL = os.environ.get("HAWKEYE_ALERTS_JSONL") or (
    _parent_alerts if os.path.exists(_parent_alerts) else "/home/fabianluna/ddos-guardian/alerts.jsonl"
)

# Puertos L7 de interes (HTTP/HTTPS/FTP/SMTP)
PORTS_OF_INTEREST = {80, 443, 8080, 21, 20, 25, 587}

# Tipos de archivo (file_type de las reglas info YARA) que consideramos
# "interesantes" y merecen detonacion dinamica.
INTERESTING_SUBSTRINGS = (
    "PDF", "OLE", "OOXML", "RTF", "Document",
    "Windows Executable", "ELF", "Bash",
)

MIN_CARVE_BYTES = 8       # payload minimo para molestarse en escanear
MAX_CARVE_BYTES = 25_000_000  # 25MB tope por archivo carveado


def _utcnow():
    return datetime.now(timezone.utc).isoformat()


def load_suspicious_ips(path=ALERTS_JSONL):
    """Lee alerts.jsonl (SOLO LECTURA, otro repo) y devuelve set de IPs sospechosas."""
    ips = set()
    if not os.path.exists(path):
        return ips
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if obj.get("ip"):
                        ips.add(obj["ip"])
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return ips


# --------------------------------------------------------------------------
# Reensamblado TCP minimo (por flujo, ordenando por numero de secuencia)
# --------------------------------------------------------------------------
class _FlowKey(tuple):
    pass


def reassemble_pcap(pcap_path):
    """Devuelve una lista de flujos reensamblados de un pcap.

    Cada elemento: dict(src, sport, dst, dport, data=bytes). Un "flujo" aca es
    una direccion de un 4-tuple (unidireccional): junta todos los segmentos TCP,
    los ordena por seq y concatena el payload -> el stream de la capa 7.
    """
    # segments[(src,sport,dst,dport)] = { seq: payload }
    segments = {}
    try:
        f = open(pcap_path, "rb")
    except OSError as e:
        print(f"[watcher] no pude abrir {pcap_path}: {e}")
        return []

    with f:
        # Detecta pcap vs pcapng por magic
        head = f.read(4)
        f.seek(0)
        try:
            if head == b"\x0a\x0d\x0d\x0a":
                reader = dpkt.pcapng.Reader(f)
            else:
                reader = dpkt.pcap.Reader(f)
        except (ValueError, dpkt.dpkt.NeedData) as e:
            print(f"[watcher] pcap invalido {pcap_path}: {e}")
            return []

        for _ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
            except Exception:
                continue
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            sport, dport = tcp.sport, tcp.dport
            if not (sport in PORTS_OF_INTEREST or dport in PORTS_OF_INTEREST):
                continue
            if not tcp.data:
                continue
            try:
                src = _ip_str(ip.src)
                dst = _ip_str(ip.dst)
            except Exception:
                continue
            key = (src, sport, dst, dport)
            segments.setdefault(key, {})[tcp.seq] = bytes(tcp.data)

    flows = []
    for (src, sport, dst, dport), segs in segments.items():
        # Ordenar por seq y concatenar (dedupe por seq ya lo da el dict)
        data = b"".join(segs[s] for s in sorted(segs))
        if len(data) >= MIN_CARVE_BYTES:
            flows.append({
                "src": src, "sport": sport, "dst": dst, "dport": dport,
                "data": data[:MAX_CARVE_BYTES],
            })
    return flows


def _ip_str(raw):
    import socket
    if len(raw) == 4:
        return socket.inet_ntoa(raw)
    return socket.inet_ntop(socket.AF_INET6, raw)


def carve_files_from_flow(flow):
    """Extrae candidatos a archivo de un stream reensamblado.

    Intenta HTTP (cuerpos de request/response); si no es HTTP, entrega el stream
    crudo como un unico candidato (FTP-data / SMTP / binario directo).
    Devuelve lista de dicts: {data, origin}.
    """
    data = flow["data"]
    candidates = []

    # --- Intento 1: HTTP responses (descargas) ---
    got_http = False
    buf = data
    for parser, label in ((dpkt.http.Response, "http_response"),
                          (dpkt.http.Request, "http_request")):
        rest = buf
        while rest:
            try:
                msg = parser(rest)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                break
            body = getattr(msg, "body", b"") or b""
            if body:
                candidates.append({"data": body, "origin": label})
                got_http = True
            consumed = len(rest) - len(getattr(msg, "data", b""))
            if consumed <= 0:
                break
            rest = getattr(msg, "data", b"")
            if not rest:
                break

    # --- Fallback: stream crudo como candidato unico ---
    if not got_http:
        candidates.append({"data": data, "origin": "raw_stream"})
    return candidates


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def scan_and_maybe_detonate(data, meta, compiled_rules, suspicious_ips,
                            detonate=True, orchestrator_timeout=180):
    """Escanea un blob con las reglas YARA info; si es interesante lo detona.

    Devuelve el dict de reporte (o None si el tipo no era interesante).
    """
    digest = _sha256(data)
    os.makedirs(CAPTURED_DIR, exist_ok=True)
    # Guardar el candidato a un archivo temporal para escanear/detonar
    tmp_path = os.path.join(CAPTURED_DIR, f"cap_{digest[:16]}.bin")
    with open(tmp_path, "wb") as f:
        f.write(data)

    scan = static_analysis.scan_file(tmp_path, compiled_rules)
    file_types = scan.get("detected_file_types", [])
    interesting = any(
        any(sub in ft for sub in INTERESTING_SUBSTRINGS) for ft in file_types
    )

    if not interesting:
        # No es un tipo interesante: descartar el temporal, no reportar.
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return None

    src_ip = meta.get("src")
    dst_ip = meta.get("dst")
    flagged = bool((src_ip in suspicious_ips) or (dst_ip in suspicious_ips))

    report = {
        "timestamp": _utcnow(),
        "sha256": digest,
        "size": len(data),
        "detected_file_types": file_types,
        "static_status": scan.get("status"),
        "static_malware_matches": scan.get("malware_matches", []),
        "flow": {k: meta.get(k) for k in ("src", "sport", "dst", "dport", "origin", "pcap")},
        "flagged_by_ddos_guardian": flagged,
        "captured_path": tmp_path,
        "detonation": None,
    }

    if detonate:
        report["detonation"] = _run_orchestrator(tmp_path, orchestrator_timeout)

    _append_report(report)
    print(f"[watcher] REPORTADO: {file_types} sha={digest[:12]} "
          f"flagged={flagged} -> {REPORTS_FILE}")
    return report


def _run_orchestrator(file_path, timeout):
    """Invoca orchestrator.py --json (mismo estilo que agent.py) y parsea la salida."""
    try:
        res = subprocess.run(
            [sys.executable, ORCHESTRATOR, "--json", file_path],
            capture_output=True, text=True, timeout=timeout,
        )
        for line in res.stdout.splitlines():
            if line.startswith("SANDBOX_RESULT_JSON: "):
                return json.loads(line[len("SANDBOX_RESULT_JSON: "):])
        return {"error": "sin SANDBOX_RESULT_JSON en salida", "stdout_tail": res.stdout[-500:]}
    except subprocess.TimeoutExpired:
        return {"error": f"orchestrator timeout ({timeout}s)"}
    except Exception as e:
        return {"error": str(e)}


def _append_report(report):
    with open(REPORTS_FILE, "a") as f:
        f.write(json.dumps(report) + "\n")


def process_pcap(pcap_path, compiled_rules=None, suspicious_ips=None,
                 detonate=True):
    """Procesa un pcap completo: reensambla, carva, escanea y detona. Devuelve #reportes."""
    if compiled_rules is None:
        compiled_rules = static_analysis.compile_rules()
    if suspicious_ips is None:
        suspicious_ips = load_suspicious_ips()

    flows = reassemble_pcap(pcap_path)
    print(f"[watcher] {os.path.basename(pcap_path)}: {len(flows)} flujo(s) L7 reensamblado(s)")
    n_reports = 0
    seen = set()
    for flow in flows:
        for cand in carve_files_from_flow(flow):
            data = cand["data"]
            if len(data) < MIN_CARVE_BYTES:
                continue
            digest = _sha256(data)
            if digest in seen:
                continue
            seen.add(digest)
            meta = {"src": flow["src"], "sport": flow["sport"],
                    "dst": flow["dst"], "dport": flow["dport"],
                    "origin": cand["origin"], "pcap": os.path.basename(pcap_path)}
            rep = scan_and_maybe_detonate(data, meta, compiled_rules,
                                          suspicious_ips, detonate=detonate)
            if rep:
                n_reports += 1
    return n_reports


def submit_file(file_path, detonate=True):
    """Somete un archivo suelto (no pcap) directamente al pipeline."""
    with open(file_path, "rb") as f:
        data = f.read()
    meta = {"src": None, "sport": None, "dst": None, "dport": None,
            "origin": "manual_submit", "pcap": None}
    rules = static_analysis.compile_rules()
    rep = scan_and_maybe_detonate(data, meta, rules, load_suspicious_ips(),
                                  detonate=detonate)
    if rep is None:
        print(f"[watcher] {file_path}: tipo no interesante, no se detona.")
    return rep


def watch_loop(interval=3, detonate=True):
    """Modo servicio: vigila pcap_in/ por nuevos pcaps y los procesa."""
    os.makedirs(PCAP_IN, exist_ok=True)
    os.makedirs(PCAP_DONE, exist_ok=True)
    rules = static_analysis.compile_rules()
    print(f"[watcher] Servicio L7 activo. Vigilando {PCAP_IN} (cada {interval}s).")
    print(f"[watcher] Reportes -> {REPORTS_FILE}")
    while True:
        suspicious = load_suspicious_ips()  # refrescar cada ciclo
        for name in sorted(os.listdir(PCAP_IN)):
            if not name.lower().endswith((".pcap", ".pcapng", ".cap")):
                continue
            path = os.path.join(PCAP_IN, name)
            print(f"[watcher] procesando {name} ...")
            try:
                process_pcap(path, rules, suspicious, detonate=detonate)
            except Exception as e:
                print(f"[watcher] error procesando {name}: {e}")
            os.replace(path, os.path.join(PCAP_DONE, name))
        time.sleep(interval)


def live_capture(iface, detonate=True):
    """Captura viva (REQUIERE root/CAP_NET_RAW). Reensambla en memoria por ventanas."""
    try:
        import pcapy  # noqa
    except ImportError:
        print("[watcher] captura viva requiere 'pcapy' o correr tshark/tcpdump a pcap.")
        print("[watcher] Alternativa sin dependencias: 'tcpdump -i IFACE -w l7_capture/pcap_in/live.pcap'")
        return
    print(f"[watcher] captura viva en {iface} (root). Implementacion via pcapy pendiente.")


def main():
    ap = argparse.ArgumentParser(description="Servicio de captura L7 -> sandbox.")
    ap.add_argument("pcap", nargs="?", help="pcap a procesar (modo one-shot)")
    ap.add_argument("--watch", action="store_true", help="modo servicio: vigila pcap_in/")
    ap.add_argument("--file", help="somete un archivo suelto (no pcap) al pipeline")
    ap.add_argument("--live", help="captura viva en la interfaz dada (requiere root)")
    ap.add_argument("--no-detonate", action="store_true",
                    help="solo carvar+clasificar, sin levantar microVM")
    ap.add_argument("--interval", type=int, default=3, help="segundos entre polls en --watch")
    args = ap.parse_args()
    detonate = not args.no_detonate

    if args.file:
        submit_file(args.file, detonate=detonate)
    elif args.live:
        live_capture(args.live, detonate=detonate)
    elif args.watch:
        watch_loop(interval=args.interval, detonate=detonate)
    elif args.pcap:
        n = process_pcap(args.pcap, detonate=detonate)
        print(f"[watcher] {n} reporte(s) generados en {REPORTS_FILE}")
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
