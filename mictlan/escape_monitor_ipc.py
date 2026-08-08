"""
escape_monitor_ipc.py — Canal entre orchestrator.py y monitor.py para marcar
el PID de cada Firecracker recien lanzado como "tainted" en el mapa BPF
tainted_pids (ver bpf/sandbox_monitor.c).

Por que un socket y no escribir el mapa BPF directamente desde
orchestrator.py: escribir en un mapa BPF requiere el syscall bpf() con
CAP_BPF/root (o unprivileged_bpf_disabled=0, que no es el default en
distros endurecidas), mientras que Firecracker en si NO necesita root en
este entorno (KVM es 0666). Forzar a orchestrator.py a tener privilegios BPF
solo para esto reintroduciria exactamente el problema de sudo que el resto
del sandbox evita a proposito (ver guest_inject.py, vm_concurrency.py).
monitor.py ya exige root para adjuntar los tracepoints y es quien posee el
objeto BPF vivo en memoria, asi que delega la escritura real a el.
"""
import json
import os
import socket

SOCK_DIR = "/tmp/hawkeye-sandbox-ipc"
SOCK_PATH = os.path.join(SOCK_DIR, "escape_monitor.sock")


def chown_to_invoking_user(path):
    """Le pasa la propiedad de `path` al usuario real que invoco `sudo` (via
    SUDO_UID/SUDO_GID), si corresponde.

    monitor.py corre como root (lo exige adjuntar las sondas eBPF), pero
    quien necesita conectarse al socket es orchestrator.py, invocado sin
    privilegios por api.py -- el mismo usuario humano real que arranco
    monitor.py via sudo en start_local.sh, solo que en otro proceso sin
    escalar. Sin este chown, el socket queda 0700 propiedad de root y
    orchestrator.py nunca puede conectarse (ver notify_tainted_pid).
    Le pasamos la propiedad al usuario real en vez de aflojar el modo:
    root sigue pudiendo administrar el socket igual (ignora permisos DAC),
    y seguimos bloqueando a cualquier OTRO usuario local del sistema, que
    es la proteccion que este 0700 buscaba en primer lugar.
    """
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if os.geteuid() == 0 and sudo_uid is not None and sudo_gid is not None:
        os.chown(path, int(sudo_uid), int(sudo_gid))


def prepare_sock_dir():
    """Crea el directorio del socket con permisos 0700 (solo llamado por
    monitor.py, dueño del socket). Evita que otro usuario local plante un
    socket/symlink ahi antes -- mismo patron que AGENT_SOCK_DIR en
    python/agent.py del proyecto hermano ddos-guardian."""
    os.makedirs(SOCK_DIR, mode=0o700, exist_ok=True)
    os.chmod(SOCK_DIR, 0o700)
    chown_to_invoking_user(SOCK_DIR)
    return SOCK_DIR


def notify_tainted_pid(pid, timeout=1.0):
    """Le avisa a monitor.py que `pid` (el proceso host de Firecracker recien
    lanzado por orchestrator.py) debe marcarse como tainted.

    Best-effort y no bloqueante para el flujo de detonacion: el monitor de
    escape es defensa en profundidad, no un requisito para poder detonar. Si
    monitor.py no esta corriendo (comun en desarrollo/pruebas manuales),
    devuelve False en vez de lanzar, y quien llama decide si loguear una
    advertencia -- mismo estilo que alert_agent() en el predictor C++ del
    proyecto hermano (conectar-si-se-puede, nunca abortar por esto).
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(SOCK_PATH)
            s.sendall((json.dumps({"pid": int(pid)}) + "\n").encode("utf-8"))
        return True
    except OSError:
        return False
