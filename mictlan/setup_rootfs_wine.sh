#!/bin/bash
#
# setup_rootfs_wine.sh — Construye la imagen base aprovisionada con Wine + Xvfb +
# app senuelo vulnerable (visor PDF). Mejoras 2 y 3.
#
# Modelo de aprovisionamiento (dado que NO hay sudo sin contrasena y no se puede
# montar rootfs.ext4 desde el host): se bootea la microVM UNA vez con red
# temporal, se instala software por apt desde adentro, se apaga, y el rootfs
# resultante queda como nueva imagen base INMUTABLE. Esto es "construccion de
# imagen", separado del paso de "detonacion" (que siempre queda air-gapped).
#
# Que hace cada fase y que privilegios necesita:
#   FASE 1 (SIN root): copia + agranda el rootfs (resize2fs sobre el archivo) e
#                      inyecta el provisioner + unit de first-boot via debugfs.
#   FASE 2 (REQUIERE root): crea la interfaz tap + NAT y bootea la VM con red
#                      para que corra el apt install. Crear tap/NAT necesita
#                      CAP_NET_ADMIN (root). Si no sos root, el script hace la
#                      FASE 1 y te imprime el comando EXACTO a correr con sudo.
#   FASE 3 (SIN root): verifica /root/.provisioned y promueve la imagen a base.
#
# Uso:
#   ./setup_rootfs_wine.sh            # hace FASE 1; FASE 2 si sos root; FASE 3
#   sudo ./setup_rootfs_wine.sh       # hace las 3 fases de corrido
#
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DATA="$DIR/vm_data"
BASE="$VM_DATA/rootfs.ext4"
KERNEL="$VM_DATA/vmlinux.bin"
FC="$DIR/firecracker"
WORK="$VM_DATA/rootfs_provision.ext4"
ASSETS="$DIR/guest_assets"
PYBIN="$DIR/venv/bin/python"

TARGET_SIZE="${TARGET_SIZE:-2048M}"     # tamano final del rootfs
VULN_APP="${VULN_APP:-xpdf}"            # app senuelo vulnerable (visor PDF)

# --- Parametros de red temporal (solo FASE 2) ---
TAP="${TAP:-fc-prov0}"
HOST_IP="172.16.0.1"
GUEST_IP="172.16.0.2"
NETMASK="255.255.255.0"
GUEST_MAC="AA:FC:00:00:00:01"

log() { echo -e "[setup] $*"; }

# ==========================================================================
# FASE 1 — resize + inyeccion del provisioner (SIN root)
# ==========================================================================
phase1_prepare() {
    log "FASE 1: preparando imagen de trabajo (sin root)."
    [ -f "$BASE" ] || { log "ERROR: no existe $BASE (corre setup_firecracker.sh)"; exit 1; }

    log "Copiando base -> $(basename "$WORK") (reflink si es btrfs)"
    cp --reflink=auto "$BASE" "$WORK"

    log "Agrandando rootfs a $TARGET_SIZE (para que entre Wine/Xvfb/$VULN_APP)"
    truncate -s "$TARGET_SIZE" "$WORK"
    e2fsck -f -y "$WORK" >/dev/null 2>&1 || true
    resize2fs "$WORK"

    log "Inyectando provisioner de first-boot via debugfs (offline, sin root)"
    "$PYBIN" - "$WORK" "$ASSETS" <<'PY'
import sys, subprocess
sys.path.insert(0, __import__("os").path.dirname(sys.argv[2]))
import guest_inject as gi
img, assets = sys.argv[1], sys.argv[2]
import os
gi.inject_file(img, os.path.join(assets, "provision_guest.sh"), "/opt/sandbox/provision_guest.sh", mode=0o755)
gi.inject_file(img, os.path.join(assets, "provision.service"), "/etc/systemd/system/provision.service", mode=0o644)
gi.mkdir_p(img, "/etc/systemd/system/multi-user.target.wants")
link = "/etc/systemd/system/multi-user.target.wants/provision.service"
if not gi.path_exists(img, link):
    subprocess.run(["debugfs","-w","-R",
        f"symlink {link} /etc/systemd/system/provision.service", img],
        capture_output=True, text=True)
print("  provisioner inyectado OK")
PY
    log "FASE 1 completa."
}

# ==========================================================================
# FASE 2 — boot con red temporal para correr apt (REQUIERE root)
# ==========================================================================
_provision_fcpid=""

# Se registra como trap de FASE 2: garantiza que el tap/NAT/firecracker de
# provisioning no queden huerfanos si el script se corta (Ctrl-C, error, kill)
# a mitad del boot con red -- antes esta limpieza solo corria al final del
# camino feliz de la funcion.
_cleanup_provision_net() {
    local out_if="$1"
    [ -n "$_provision_fcpid" ] && kill "$_provision_fcpid" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o "$out_if" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$TAP" -o "$out_if" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$out_if" -o "$TAP" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    ip link set "$TAP" down 2>/dev/null || true
    ip tuntap del dev "$TAP" mode tap 2>/dev/null || true
}

phase2_provision() {
    log "FASE 2: aprovisionamiento con red (requiere root)."
    local out_if
    out_if="$(ip route show default | awk '/default/{print $5; exit}')"
    trap '_cleanup_provision_net "$out_if"' EXIT INT TERM

    # Limpiar restos de ejecuciones previas de firecracker o interfaz tap
    pkill -f "$FC" 2>/dev/null || true
    ip link set "$TAP" down 2>/dev/null || true
    ip tuntap del dev "$TAP" mode tap 2>/dev/null || true

    log "Creando tap $TAP ($HOST_IP) + NAT hacia $out_if"
    ip tuntap add dev "$TAP" mode tap 2>/dev/null || true
    ip addr add "$HOST_IP/24" dev "$TAP" 2>/dev/null || true
    ip link set "$TAP" up
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    iptables -t nat -C POSTROUTING -o "$out_if" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o "$out_if" -j MASQUERADE
    iptables -C FORWARD -i "$TAP" -o "$out_if" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$TAP" -o "$out_if" -j ACCEPT
    iptables -C FORWARD -i "$out_if" -o "$TAP" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$out_if" -o "$TAP" -m state --state RELATED,ESTABLISHED -j ACCEPT

    local cfg="$VM_DATA/provision_vm_config.json"
    cat > "$cfg" <<EOF
{
  "boot-source": {
    "kernel_image_path": "$KERNEL",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ip=$GUEST_IP::$HOST_IP:$NETMASK::eth0:off"
  },
  "drives": [
    {"drive_id": "rootfs", "path_on_host": "$WORK", "is_root_device": true, "is_read_only": false}
  ],
  "network-interfaces": [
    {"iface_id": "eth0", "host_dev_name": "$TAP", "guest_mac": "$GUEST_MAC"}
  ],
  "machine-config": {"vcpu_count": 2, "mem_size_mib": 1024, "smt": false}
}
EOF

    local sock="$DIR/provision.socket"
    rm -f "$sock"
    log "Booteando VM de provisioning (apt install puede tardar varios minutos)..."
    VULN_APP="$VULN_APP" "$FC" --api-sock "$sock" --config-file "$cfg" &
    _provision_fcpid=$!

    # Esperar hasta 20 min a que el guest termine e apague (poweroff -> FC sale)
    local waited=0
    while kill -0 "$_provision_fcpid" 2>/dev/null; do
        sleep 5; waited=$((waited+5))
        if [ "$waited" -ge 1200 ]; then
            log "Timeout de provisioning; matando VM."
            kill "$_provision_fcpid" 2>/dev/null || true
            break
        fi
    done
    wait "$_provision_fcpid" 2>/dev/null || true
    rm -f "$cfg" "$sock"

    # Camino feliz: limpiamos ya (no esperar al EXIT trap del script entero) y
    # desarmamos el trap para no limpiar dos veces.
    log "Limpiando red temporal (tap + reglas NAT)"
    trap - EXIT INT TERM
    _cleanup_provision_net "$out_if"
    log "FASE 2 completa."
}

# ==========================================================================
# FASE 3 — verificar y promover a imagen base (SIN root)
# ==========================================================================
phase3_promote() {
    log "FASE 3: verificando provisioning."
    local prov
    prov="$(debugfs -R "cat /root/.provisioned" "$WORK" 2>/dev/null | grep -v '^debugfs' || true)"
    if echo "$prov" | grep -q "wine=/"; then
        log "Provisioning OK:"
        echo "$prov" | sed 's/^/    /'
        # IMPORTANTE: quitar el unit de provisioning para que NO vuelva a correr
        # (y no deje red pedida) en las detonaciones futuras.
        debugfs -w -R "rm /etc/systemd/system/multi-user.target.wants/provision.service" "$WORK" 2>/dev/null || true
        cp -f "$BASE" "$VM_DATA/rootfs.ext4.pre-wine.bak"
        mv -f "$WORK" "$BASE"
        log "Nueva imagen base promovida. Backup: rootfs.ext4.pre-wine.bak"
        log "Ya podes detonar .exe (wine) y documentos (visor vulnerable)."
    else
        log "ERROR: /root/.provisioned no confirma Wine. Revisa el boot de provisioning."
        log "La imagen de trabajo quedo en: $WORK (no se promovio)."
        return 1
    fi
}

# ==========================================================================
main() {
    phase1_prepare
    if [ "$(id -u)" -eq 0 ]; then
        phase2_provision
        phase3_promote
    else
        cat <<EOF

============================================================================
[setup] FASE 1 lista. La FASE 2 (crear tap + NAT + bootear con red para apt)
[setup] REQUIERE ROOT (CAP_NET_ADMIN). Corre EXACTAMENTE:

    sudo TARGET_SIZE=$TARGET_SIZE VULN_APP=$VULN_APP $DIR/setup_rootfs_wine.sh

[setup] Eso reusa la imagen ya preparada ($WORK), instala Wine+Xvfb+$VULN_APP,
[setup] y promueve el resultado a $BASE (con backup .pre-wine.bak).
============================================================================
EOF
    fi
}
main "$@"
