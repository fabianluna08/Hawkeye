"""Fase 0 — línea base honesta.

Dos niveles de test:

1. Lógica pura de scripts/baseline_report.py (decodificación de ip_key_t,
   cálculo de ratios, cruce con alerts.jsonl) — corre siempre, sin root.
2. Contador real baseline_map en kern/xdp_kern.c vía un veth pair con XDP
   cargado de verdad — requiere root, CAP_NET_ADMIN, bpftool, clang, scapy y
   `ip link ... type veth` funcional (no siempre disponible en contenedores
   sin --privileged, ni en CI estándar). Se salta automáticamente si falta
   cualquiera de esos requisitos, en vez de fallar el suite completo.
"""

import importlib.util
import json
import os
import shutil
import socket
import struct
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
KERN_OBJ = REPO_ROOT / "xdp_kern.o"


def _load_baseline_report():
    spec = importlib.util.spec_from_file_location(
        "baseline_report", REPO_ROOT / "scripts" / "baseline_report.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def br():
    return _load_baseline_report()


# ──────────────────────────────────────────────────────────────
# 1) Lógica pura — sin root, sin BPF
# ──────────────────────────────────────────────────────────────

def test_decode_ip_key_ipv4(br):
    ip = "203.0.113.7"
    raw = socket.inet_aton(ip)
    word = struct.unpack("<I", raw)[0]
    key = {"ip": [word, 0, 0, 0], "is_v6": 0, "pad": [0, 0, 0]}
    assert br._decode_ip_key(key) == ip


def test_decode_ip_key_ipv6(br):
    ip6 = "2001:db8::abcd"
    raw6 = socket.inet_pton(socket.AF_INET6, ip6)
    words = [struct.unpack("<I", raw6[i:i + 4])[0] for i in range(0, 16, 4)]
    key = {"ip": words, "is_v6": 1, "pad": [0, 0, 0]}
    assert br._decode_ip_key(key) == ip6


def test_build_report_encrypted_ratio_and_malicious_rate(br):
    start = datetime(2026, 7, 15, tzinfo=timezone.utc)
    end = start + timedelta(hours=1)
    first = dict.fromkeys(
        ["total_pkts", "total_bytes", "tcp443_pkts", "tcp443_bytes", "udp443_pkts", "udp443_bytes"], 0
    )
    last = {
        "total_pkts": 1000, "total_bytes": 100_000,
        "tcp443_pkts": 800, "tcp443_bytes": 85_000,
        "udp443_pkts": 50, "udp443_bytes": 5_000,
    }
    tracked = {"1.2.3.4", "5.6.7.8"}
    blocked = {"5.6.7.8"}
    confirmed = {"5.6.7.8"}

    report = br.build_report(start, end, last, first, tracked, blocked, confirmed, 3, 10)

    assert report["encrypted_traffic_ratio_bytes"] == pytest.approx(0.9)
    assert report["encrypted_traffic_ratio_pkts"] == pytest.approx(0.85)
    assert report["distinct_ips_tracked"] == 2
    assert report["malicious_flow_rate_by_block_map"] == pytest.approx(0.5)
    assert report["malicious_flow_rate_by_confirmed_alerts"] == pytest.approx(0.5)


def test_build_report_handles_no_traffic_without_dividing_by_zero(br):
    start = datetime(2026, 7, 15, tzinfo=timezone.utc)
    end = start + timedelta(hours=1)
    report = br.build_report(start, end, None, None, set(), set(), set(), 0, 0)
    assert report["encrypted_traffic_ratio_bytes"] is None
    assert report["malicious_flow_rate_by_block_map"] is None


def test_read_confirmed_alerts_filters_by_window_and_confirmado(br, tmp_path, monkeypatch):
    alerts = tmp_path / "alerts.jsonl"
    start = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
    end = start + timedelta(minutes=10)
    in_window = (start + timedelta(minutes=1)).isoformat()
    out_of_window = (start - timedelta(hours=1)).isoformat()
    lines = [
        {"ip": "10.0.0.1", "confirmado": True, "timestamp": in_window},
        {"ip": "10.0.0.2", "confirmado": False, "timestamp": in_window},  # no confirmada
        {"ip": "10.0.0.3", "confirmado": True, "timestamp": out_of_window},  # fuera de ventana
        {"ip": "10.0.0.1", "confirmado": True, "timestamp": in_window},  # IP repetida
    ]
    alerts.write_text("\n".join(json.dumps(a) for a in lines))
    monkeypatch.setattr(br, "ALERTS_PATH", alerts)

    ips, total = br.read_confirmed_alerts(start, end)

    assert ips == {"10.0.0.1"}
    assert total == 2  # dos líneas confirmadas dentro de ventana, aunque sea la misma IP


# ──────────────────────────────────────────────────────────────
# 2) baseline_map real sobre veth + XDP cargado — requiere root
# ──────────────────────────────────────────────────────────────

def _is_root():
    return os.geteuid() == 0


def _has_tools():
    return all(shutil.which(t) for t in ("ip", "bpftool"))


def _veth_supported():
    """Prueba real de creación de veth, no solo presencia de `ip`: en
    contenedores sin --privileged o sin namespace de red propio, `ip link
    add type veth` falla aunque el binario exista."""
    if not _is_root() or not _has_tools():
        return False
    name = "hawkeye-veth-probe"
    r = subprocess.run(
        ["ip", "link", "add", name, "type", "veth", "peer", "name", f"{name}-p"],
        capture_output=True,
    )
    if r.returncode == 0:
        subprocess.run(["ip", "link", "del", name], capture_output=True)
        return True
    return False


requires_privileged_net = pytest.mark.skipif(
    not (_is_root() and _has_tools() and KERN_OBJ.exists() and _veth_supported()),
    reason=(
        "requiere root + CAP_NET_ADMIN + bpftool + xdp_kern.o compilado "
        "(`make kern`) + soporte real de veth en este entorno"
    ),
)

try:
    import scapy.all as _scapy  # noqa: F401
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False

requires_scapy = pytest.mark.skipif(not _HAS_SCAPY, reason="scapy no instalado (ver requirements-dev.txt)")


@pytest.fixture
def veth_pair():
    host_if, peer_if = "hveth-host", "hveth-peer"
    subprocess.run(["ip", "link", "del", host_if], capture_output=True)
    subprocess.run(
        ["ip", "link", "add", host_if, "type", "veth", "peer", "name", peer_if],
        check=True,
    )
    subprocess.run(["ip", "link", "set", host_if, "up"], check=True)
    subprocess.run(["ip", "link", "set", peer_if, "up"], check=True)
    subprocess.run(["ip", "addr", "add", "10.250.0.1/24", "dev", host_if], check=True)
    subprocess.run(["ip", "addr", "add", "10.250.0.2/24", "dev", peer_if], check=True)
    try:
        yield host_if, peer_if
    finally:
        subprocess.run(["ip", "link", "set", host_if, "xdp", "off"], capture_output=True)
        subprocess.run(["ip", "link", "del", host_if], capture_output=True)


@requires_privileged_net
@requires_scapy
def test_baseline_map_counts_tcp443_and_total(veth_pair):
    from scapy.all import IP, TCP, UDP, Ether, sendp

    host_if, peer_if = veth_pair

    load = subprocess.run(
        ["ip", "link", "set", "dev", host_if, "xdp", "obj", str(KERN_OBJ), "sec", "xdp"],
        capture_output=True, text=True,
    )
    assert load.returncode == 0, f"no se pudo cargar xdp_kern.o: {load.stderr}"

    n_tcp443, n_udp443, n_other = 5, 3, 4
    pkts = (
        [Ether() / IP(dst="10.250.0.1") / TCP(dport=443) for _ in range(n_tcp443)]
        + [Ether() / IP(dst="10.250.0.1") / UDP(dport=443) for _ in range(n_udp443)]
        + [Ether() / IP(dst="10.250.0.1") / TCP(dport=8080) for _ in range(n_other)]
    )
    sendp(pkts, iface=peer_if, verbose=False)
    time.sleep(0.5)

    dump = subprocess.run(
        ["bpftool", "map", "dump", "name", "baseline_map", "-j"],
        capture_output=True, text=True, check=True,
    )
    entries = json.loads(dump.stdout)
    totals = {}
    for percpu in entries[0]["values"]:
        for field, v in percpu["value"].items():
            totals[field] = totals.get(field, 0) + v

    assert totals["total_pkts"] == n_tcp443 + n_udp443 + n_other
    assert totals["tcp443_pkts"] == n_tcp443
    assert totals["udp443_pkts"] == n_udp443
