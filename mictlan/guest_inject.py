"""
guest_inject.py — Inyeccion y extraccion de archivos dentro de imagenes ext4
SIN privilegios de root, usando `debugfs` (paquete e2fsprogs).

Motivacion / decision de diseno
--------------------------------
En este entorno NO hay sudo sin contrasena, por lo que `losetup`/`mount` para
manipular `rootfs.ext4` directamente desde el host no son viables (se cuelgan o
fallan). `debugfs` puede leer Y escribir un sistema de archivos ext2/3/4 offline
operando sobre el archivo imagen crudo, siempre que el usuario tenga permiso de
escritura sobre ese archivo. Verificado funcionando sin root en este entorno.

Se usa para:
  - Inyectar el payload a detonar dentro del disco COW efimero antes de bootear
    la microVM (air-gap: no hace falta red para meter el archivo adentro).
  - Inyectar scripts de autostart, documentos senuelo y "archivos recientes"
    falsos (anti-evasion, Mejora 3).
  - Extraer telemetria/artefactos del disco COW DESPUES de apagar la VM pero
    ANTES de destruirlo (Mejora 2), sin darle red a la VM.

Todas las operaciones son offline sobre el .ext4; la VM debe estar apagada.
"""
import os
import re
import shlex
import subprocess
import tempfile

DEBUGFS = "debugfs"

# debugfs parsea sus comandos linea por linea con su propio tokenizador (no es
# un shell): shlex.quote() protege argumentos con espacios, pero NO garantiza
# nada frente a un guest_path con un salto de linea (inyectaria un comando
# debugfs entero aparte) o retorno de carro. Cualquier guest_path que llegue
# a `_run_debugfs`/`-R` pasa por esta validacion, sea cual sea el llamador.
_FORBIDDEN_IN_PATH = re.compile(r"[\r\n\x00]")


class GuestInjectError(RuntimeError):
    pass


def sanitize_guest_component(name, default="file.bin", max_len=120):
    """Reduce `name` (ej. el nombre original de un payload no confiable) a un
    componente de ruta seguro: solo [A-Za-z0-9._-], sin '..' ni nombres vacios.

    Usar SIEMPRE que un nombre de archivo con origen externo (payload
    analizado, upload, etc.) vaya a formar parte de un guest_path.
    """
    base = os.path.basename(name or "")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    safe = safe[:max_len]
    return safe or default


def _validate_guest_path(path):
    if _FORBIDDEN_IN_PATH.search(path):
        raise GuestInjectError(
            f"guest_path contiene caracteres no permitidos (CR/LF/NUL): {path!r}"
        )
    return path


def _run_debugfs(image_path, commands, writable):
    """Ejecuta una secuencia de comandos debugfs sobre `image_path`.

    `commands` es una lista de strings (comandos debugfs). Se pasan via un
    archivo de comandos (-f) para poder batchear varias operaciones en una
    sola invocacion. Devuelve el stdout combinado.
    """
    if not os.path.exists(image_path):
        raise GuestInjectError(f"Imagen no encontrada: {image_path}")
    for c in commands:
        _validate_guest_path(c)

    with tempfile.NamedTemporaryFile("w", suffix=".debugfs", delete=False) as cf:
        cf.write("\n".join(commands) + "\n")
        cmd_file = cf.name
    try:
        args = [DEBUGFS]
        if writable:
            args.append("-w")
        args += ["-f", cmd_file, image_path]
        proc = subprocess.run(args, capture_output=True, text=True)
        # debugfs escribe ruido de version en stderr; solo fallamos por returncode.
        if proc.returncode != 0:
            raise GuestInjectError(
                f"debugfs fallo (rc={proc.returncode}) sobre {image_path}: "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        return proc.stdout
    finally:
        os.unlink(cmd_file)


def _guest_dirname(guest_path):
    d = os.path.dirname(guest_path.rstrip("/"))
    return d or "/"


def path_exists(image_path, guest_path):
    """True si `guest_path` existe dentro de la imagen.

    Nota: debugfs reporta "File not found by ext2_lookup" por STDERR (no stdout)
    y con returncode 0, por eso capturamos ambos flujos aca directamente.
    """
    _validate_guest_path(guest_path)
    proc = subprocess.run(
        [DEBUGFS, "-R", f"stat {guest_path}", image_path],
        capture_output=True, text=True,
    )
    combined = proc.stdout + proc.stderr
    return "File not found" not in combined and "not found by" not in combined


def _mkdir_p_commands(guest_dir):
    """Genera comandos debugfs para crear guest_dir y sus padres (mkdir -p)."""
    parts = [p for p in guest_dir.strip("/").split("/") if p]
    cmds = []
    accum = ""
    for p in parts:
        accum += "/" + p
        # debugfs mkdir falla si ya existe; lo toleramos con 'testb'-free approach:
        # usamos '-R' individual mas abajo. Aca devolvemos mkdir; los errores de
        # "ya existe" se ignoran porque no cambian returncode a nivel batch salvo
        # el ultimo. Para robustez creamos con comando aparte tolerante.
        cmds.append(accum)
    return cmds


def mkdir_p(image_path, guest_dir):
    """Crea guest_dir dentro de la imagen (equivalente a mkdir -p)."""
    _validate_guest_path(guest_dir)
    for d in _mkdir_p_commands(guest_dir):
        # Ejecutamos cada mkdir por separado y toleramos "ya existe".
        proc = subprocess.run(
            [DEBUGFS, "-w", "-R", f"mkdir {d}", image_path],
            capture_output=True, text=True,
        )
        combined = (proc.stdout + proc.stderr)
        if proc.returncode != 0 and "File exists" not in combined:
            raise GuestInjectError(f"mkdir {d} fallo: {combined.strip()}")


def inject_file(image_path, host_path, guest_path, mode=None):
    """Copia host_path -> guest_path dentro de la imagen ext4 (offline, sin root).

    Crea los directorios padre necesarios y sobrescribe si ya existe.
    `mode` opcional en octal (int, ej 0o755) fija los permisos del archivo.
    """
    if not os.path.exists(host_path):
        raise GuestInjectError(f"Archivo host no encontrado: {host_path}")

    guest_dir = _guest_dirname(guest_path)
    if guest_dir not in ("/", ""):
        mkdir_p(image_path, guest_dir)

    cmds = []
    if path_exists(image_path, guest_path):
        cmds.append(f"rm {guest_path}")
    cmds.append(f"write {shlex.quote(host_path)} {guest_path}")
    if mode is not None:
        # `sif mode` fija el i_mode COMPLETO (incluye bits de tipo de archivo).
        # Preservamos S_IFREG (0o100000) para no corromper el tipo del inode.
        full = 0o100000 | (mode & 0o7777)
        cmds.append(f"sif {guest_path} mode 0{oct(full)[2:]}")
    _run_debugfs(image_path, cmds, writable=True)


def inject_bytes(image_path, data, guest_path, mode=None):
    """Como inject_file pero desde bytes/str en memoria."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data)
        tmp = tf.name
    try:
        inject_file(image_path, tmp, guest_path, mode=mode)
    finally:
        os.unlink(tmp)


def extract_file(image_path, guest_path, host_path):
    """Copia guest_path (dentro de la imagen) -> host_path. Devuelve True si existio."""
    if not path_exists(image_path, guest_path):
        return False
    os.makedirs(os.path.dirname(os.path.abspath(host_path)), exist_ok=True)
    _run_debugfs(image_path, [f"dump {guest_path} {shlex.quote(host_path)}"], writable=False)
    return os.path.exists(host_path)


def extract_dir(image_path, guest_dir, host_dir):
    """Extrae recursivamente guest_dir -> host_dir (rdump). Devuelve True si existio."""
    if not path_exists(image_path, guest_dir):
        return False
    os.makedirs(host_dir, exist_ok=True)
    _run_debugfs(image_path, [f"rdump {guest_dir} {shlex.quote(host_dir)}"], writable=False)
    return True


def read_file_text(image_path, guest_path, default=""):
    """Devuelve el contenido de texto de guest_path, o `default` si no existe."""
    if not path_exists(image_path, guest_path):
        return default
    out = _run_debugfs(image_path, [f"cat {guest_path}"], writable=False)
    # En modo -f, debugfs hace eco del prompt "debugfs:  cat ..." y de la linea
    # de version "debugfs 1.47...". Filtramos ambas.
    lines = [
        ln for ln in out.splitlines()
        if not ln.startswith("debugfs ") and not ln.startswith("debugfs:")
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    print("guest_inject.py — helpers debugfs (uso via import). Args:", sys.argv[1:])
