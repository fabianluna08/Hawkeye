#!/bin/bash
# detonate.sh — Runner de detonacion DENTRO del guest (air-gapped).
#
# Lo lanza `detonate.service` (oneshot systemd) al bootear la microVM. Lee la
# tarea inyectada offline en /opt/sandbox/task.json, ejecuta el payload segun su
# modo (linux / wine / document), recolecta telemetria de ejecucion y la deja en
# /root/sandbox_telemetry/ para que el host la extraiga con debugfs DESPUES de
# apagar la VM (sin red: air-gap intacto). Al terminar apaga la VM para que
# Firecracker salga y el host siga con la extraccion + destruccion del COW.
#
# IMPORTANTE: este script NO asume que wine/xvfb/visor esten instalados. Si
# faltan (p.ej. antes de correr setup_rootfs_wine.sh) lo registra en la
# telemetria y termina limpio, de modo que el pipeline de telemetria se puede
# validar aun sin el aprovisionamiento pesado.

set +e
export HOME=/root
export DISPLAY=:99

TASK=/opt/sandbox/task.json
OUT=/root/sandbox_telemetry
mkdir -p "$OUT"
LOG="$OUT/detonation.log"
REPORT="$OUT/report.json"
exec > >(tee -a "$LOG") 2>&1

echo "[guest] detonate.sh iniciado $(date -u +%FT%TZ)"

# --- Parse minimal JSON sin jq (puede no estar en la imagen minimizada) ---
jget() { grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$TASK" | head -1 | sed 's/.*:[[:space:]]*"\(.*\)"/\1/'; }
jgetnum() { grep -o "\"$1\"[[:space:]]*:[[:space:]]*[0-9]*" "$TASK" | head -1 | grep -o '[0-9]*$'; }

MODE="$(jget mode)"
PAYLOAD="$(jget payload_guest_path)"
VIEWER="$(jget viewer)"
TIMEOUT="$(jgetnum timeout)"
[ -z "$TIMEOUT" ] && TIMEOUT=45

echo "[guest] mode=$MODE payload=$PAYLOAD viewer=$VIEWER timeout=$TIMEOUT"

# --- Estado pre-ejecucion (para diff de artefactos) ---
# sleep 1 tras el marker: garantiza que los archivos que escriba el payload
# tengan mtime ESTRICTAMENTE mayor (find -newer excluye timestamps iguales, y
# en ejecuciones sub-segundo el marker y los artefactos podrian empatar).
MARKER=/root/.detonate_marker
touch "$MARKER"
sleep 1
ps -eo pid,ppid,comm > "$OUT/ps_before.txt" 2>/dev/null

STDOUT_F="$OUT/payload_stdout.txt"
EXIT_CODE="n/a"
CRASHED="false"
TOOL_MISSING=""

run_with_timeout() { timeout -s KILL "$TIMEOUT" "$@"; }

case "$MODE" in
  linux)
    if [ -f "$PAYLOAD" ]; then
      chmod +x "$PAYLOAD" 2>/dev/null
      run_with_timeout "$PAYLOAD" > "$STDOUT_F" 2>&1
      EXIT_CODE=$?
    else
      echo "[guest] payload no encontrado: $PAYLOAD" > "$STDOUT_F"
    fi
    ;;
  wine)
    if command -v wine >/dev/null 2>&1; then
      # Xvfb headless para que las GUI de Windows tengan display
      if command -v Xvfb >/dev/null 2>&1; then
        Xvfb :99 -screen 0 1024x768x16 >/dev/null 2>&1 &
        XVFB_PID=$!
        sleep 2
      else
        TOOL_MISSING="Xvfb"
      fi
      run_with_timeout wine "$PAYLOAD" > "$STDOUT_F" 2>&1
      EXIT_CODE=$?
      [ -n "$XVFB_PID" ] && kill "$XVFB_PID" 2>/dev/null
    else
      TOOL_MISSING="wine"
      echo "[guest] wine NO instalado. Corre setup_rootfs_wine.sh (paso root)." > "$STDOUT_F"
    fi
    ;;
  document)
    # Abrir el documento con la app senuelo vulnerable para que un exploit
    # embebido tenga blanco. Xvfb da display headless.
    [ -z "$VIEWER" ] && VIEWER="xpdf"
    if command -v "$VIEWER" >/dev/null 2>&1; then
      if command -v Xvfb >/dev/null 2>&1; then
        Xvfb :99 -screen 0 1024x768x16 >/dev/null 2>&1 &
        XVFB_PID=$!
        sleep 2
      else
        TOOL_MISSING="Xvfb"
      fi
      run_with_timeout "$VIEWER" "$PAYLOAD" > "$STDOUT_F" 2>&1
      EXIT_CODE=$?
      [ -n "$XVFB_PID" ] && kill "$XVFB_PID" 2>/dev/null
    else
      TOOL_MISSING="$VIEWER"
      echo "[guest] visor $VIEWER NO instalado. Corre setup_rootfs_wine.sh." > "$STDOUT_F"
    fi
    ;;
  *)
    echo "[guest] modo desconocido: $MODE" > "$STDOUT_F"
    ;;
esac

# timeout devuelve 137 (128+SIGKILL) si mato el proceso por exceder tiempo
if [ "$EXIT_CODE" = "137" ]; then CRASHED="timeout"; fi
# codigos > 128 suelen indicar terminacion por senal (segfault=139, etc.)
if [ "$EXIT_CODE" != "n/a" ] && [ "$EXIT_CODE" -gt 128 ] 2>/dev/null; then CRASHED="signal_$((EXIT_CODE-128))"; fi

# --- Post-ejecucion: procesos y artefactos nuevos ---
ps -eo pid,ppid,comm > "$OUT/ps_after.txt" 2>/dev/null
# Archivos escritos/modificados desde el marker en zonas tipicas
find /root /home /tmp /var/tmp /etc -newer "$MARKER" -type f 2>/dev/null \
  | grep -v "$OUT" > "$OUT/files_written.txt"
# dmesg captura segfaults / oops del kernel del guest
dmesg 2>/dev/null | tail -40 > "$OUT/dmesg_tail.txt"

FILES_COUNT=$(wc -l < "$OUT/files_written.txt" 2>/dev/null | tr -d ' ')

# --- Reporte JSON (escrito a mano para no depender de jq/python en el guest) ---
esc() { sed 's/\\/\\\\/g; s/"/\\"/g' ; }
{
  echo "{"
  echo "  \"mode\": \"$MODE\","
  echo "  \"payload_guest_path\": \"$PAYLOAD\","
  echo "  \"exit_code\": \"$EXIT_CODE\","
  echo "  \"crashed\": \"$CRASHED\","
  echo "  \"tool_missing\": \"$TOOL_MISSING\","
  echo "  \"files_written_count\": ${FILES_COUNT:-0},"
  echo "  \"finished_utc\": \"$(date -u +%FT%TZ)\""
  echo "}"
} > "$REPORT"

echo "[guest] detonacion completa. exit=$EXIT_CODE crashed=$CRASHED files=$FILES_COUNT"
sync
sleep 1
# Apagar para que Firecracker SALGA. Debe ser un REBOOT (reset), no un halt:
# con boot_args 'reboot=k' el reset via keyboard-controller hace que Firecracker
# detecte el reset y termine el proceso. Un 'poweroff' deja al guest en "System
# halted" y Firecracker seguiria vivo (el host tendria que matarlo por timeout).
reboot -f 2>/dev/null || systemctl reboot -i 2>/dev/null || echo b > /proc/sysrq-trigger
