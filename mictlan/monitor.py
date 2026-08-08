from bcc import BPF
import ctypes as ct
import json
import os
import socketserver
import sys
import threading

import escape_monitor_ipc as ipc

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BPF_FILE = os.path.join(SCRIPT_DIR, "bpf/sandbox_monitor.c")


def print_event(cpu, data, size):
    event = b["events"].event(data)
    filename = event.filename.decode("utf-8", "replace")
    comm = event.comm.decode("utf-8", "replace")
    via = "execveat" if event.via_execveat else "execve"
    print(f"ALARM: Sandbox Escape Attempt Detected! [PID: {event.pid}] "
          f"Process '{comm}' executed host binary via {via}: {filename}")


def _mark_tainted(pid):
    """Inserta `pid` en el mapa BPF tainted_pids. bpf_kern.c se encarga de
    propagar la marca a los hijos en cada fork (ver TRACEPOINT_PROBE de
    sched_process_fork), asi que solo hace falta marcar el PID inicial de
    Firecracker una vez por detonacion."""
    key = ct.c_uint32(int(pid))
    val = ct.c_uint8(1)
    b["tainted_pids"][key] = val
    print(f"[*] PID {pid} marcado como Firecracker (tainted) — se vigilan sus execve/execveat.")


class _NotifyHandler(socketserver.BaseRequestHandler):
    """Atiende una notificacion de orchestrator.py por conexion (una linea
    JSON con el PID a marcar) y cierra."""

    def handle(self):
        try:
            chunk = self.request.recv(4096)
        except OSError:
            return
        if not chunk:
            return
        for line in chunk.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                _mark_tainted(msg["pid"])
            except (ValueError, KeyError, TypeError) as e:
                print(f"[!] Notificacion de PID tainted invalida ({line!r}): {e}")


def _start_notify_server():
    ipc.prepare_sock_dir()
    if os.path.exists(ipc.SOCK_PATH):
        os.remove(ipc.SOCK_PATH)
    server = socketserver.ThreadingUnixStreamServer(ipc.SOCK_PATH, _NotifyHandler)
    os.chmod(ipc.SOCK_PATH, 0o600)
    ipc.chown_to_invoking_user(ipc.SOCK_PATH)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Escuchando notificaciones de PIDs tainted en {ipc.SOCK_PATH}")
    return server


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges to attach eBPF probes.")
        sys.exit(1)

    print("Loading eBPF sandbox monitor...")
    try:
        with open(BPF_FILE, "r") as f:
            bpf_text = f.read()
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"Failed to compile eBPF program: {e}")
        sys.exit(1)

    notify_server = _start_notify_server()

    print("eBPF Sandbox Monitor loaded! Tracing tainted-PID host escapes... Ctrl-C to exit.")

    b["events"].open_perf_buffer(print_event)
    try:
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    except Exception as e:
        print(f"Error polling perf buffer: {e}")
    finally:
        notify_server.shutdown()
        try:
            os.remove(ipc.SOCK_PATH)
        except OSError:
            pass
