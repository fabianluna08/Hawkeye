"""
vm_concurrency.py — Limite de VMs Firecracker concurrentes (cross-process).

Cada detonacion se lanza como un proceso `orchestrator.py` independiente (lo
invoca agent.py o el watcher L7 por subprocess), por lo que un semaforo en
memoria (threading.Semaphore) NO alcanza: el limite debe ser compartido entre
procesos distintos. Se implementa con `flock` (fcntl) sobre N archivos-slot en
un directorio: adquirir una VM = tomar el flock exclusivo de cualquiera de los
N slots. Al morir el proceso (incluso si crashea) el kernel libera el flock
automaticamente, asi que no quedan slots "colgados".

Config:
  SANDBOX_MAX_VMS (env)  numero maximo de VMs concurrentes. Default 3.
    Justificacion default: cada VM usa 512MB (mem_size_mib). La maquina tiene
    ~11GB totales; 3 VMs = ~1.5GB, holgado dejando RAM para host + watcher.
  SANDBOX_SLOT_DIR (env) directorio de slots. Default <script_dir>/.vm_slots
"""
import fcntl
import os
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def get_max_vms():
    try:
        return max(1, int(os.environ.get("SANDBOX_MAX_VMS", "3")))
    except ValueError:
        return 3


def _slot_dir():
    d = os.environ.get("SANDBOX_SLOT_DIR", os.path.join(SCRIPT_DIR, ".vm_slots"))
    os.makedirs(d, exist_ok=True)
    return d


class VMSlot:
    """Context manager que reserva un slot de VM (bloqueante hasta timeout).

    Uso:
        with VMSlot(timeout=120) as slot:
            ...  # levantar la microVM aqui
    Levanta TimeoutError si no consigue slot dentro de `timeout` segundos.
    """

    def __init__(self, timeout=300, poll_interval=0.5):
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.max_vms = get_max_vms()
        self.slot_dir = _slot_dir()
        self._fd = None
        self.index = None

    def _try_acquire(self):
        for i in range(self.max_vms):
            path = os.path.join(self.slot_dir, f"slot_{i}.lock")
            # O_NOFOLLOW: si slot_dir fuera compartido con otro usuario, evita
            # que un symlink plantado ahi (ej. -> /root/.ssh/authorized_keys)
            # termine truncado por el os.ftruncate(fd, 0) de mas abajo.
            try:
                fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o644)
            except OSError:
                continue
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                continue
            # Slot adquirido: dejamos rastro de quien lo tiene (informativo).
            try:
                os.ftruncate(fd, 0)
                os.write(fd, f"pid={os.getpid()} t={time.time():.0f}\n".encode())
            except OSError:
                pass
            self._fd = fd
            self.index = i
            return True
        return False

    def acquire(self):
        deadline = time.time() + self.timeout
        while True:
            if self._try_acquire():
                return self
            if time.time() >= deadline:
                raise TimeoutError(
                    f"No hay slot de VM libre tras {self.timeout}s "
                    f"(SANDBOX_MAX_VMS={self.max_vms})"
                )
            time.sleep(self.poll_interval)

    def release(self):
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()
        return False
