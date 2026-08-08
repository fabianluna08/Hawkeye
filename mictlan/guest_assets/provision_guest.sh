#!/bin/bash
# provision_guest.sh — Se ejecuta DENTRO del guest UNA sola vez (first-boot) con
# red temporal, para instalar Wine + Xvfb + la app senuelo vulnerable (visor PDF)
# en la imagen base. Este es el paso de "CONSTRUCCION DE IMAGEN", separado y
# distinto del paso de "DETONACION" (que siempre queda air-gapped). Al terminar
# apaga la VM; el host se queda con este rootfs como nueva imagen base inmutable.
#
# App senuelo vulnerable (Mejora 3): xpdf (visor PDF liviano y notoriamente
# historico por CVEs de corrupcion de memoria al parsear PDFs malformados, p.ej.
# CVE-2019-13288 recursion no controlada en XRef::fetch, CVE-2018-16369 stack
# overflow, familia CVE-2007-xxxx/CVE-2010-3702). Sirve como blanco realista para
# que un PDF con exploit embebido tenga contra que dispararse dentro del guest
# air-gapped. Ajustable via VULN_APP.
set -x
export DEBIAN_FRONTEND=noninteractive
export HOME=/root

VULN_APP="${VULN_APP:-xpdf}"

# --- Red temporal (config estatica via kernel cmdline ip=, ver setup script) ---
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf
ip link set eth0 up 2>/dev/null
# Si el cmdline no configuro la IP, intentar estatica de respaldo:
ip addr show eth0 | grep -q "inet " || ip addr add 172.16.0.2/24 dev eth0 2>/dev/null
ip route | grep -q default || ip route add default via 172.16.0.1 2>/dev/null

echo "[provision] probando conectividad..."
mkdir -p /var/lib/dpkg
touch /var/lib/dpkg/status
if ! timeout 10 apt-get update; then
    echo "[provision] ERROR: sin red/DNS. Revisa tap+NAT en el host." | tee /root/PROVISION_FAILED
    sleep 2
    poweroff -f
    exit 1
fi

# --- Instalacion de paquetes ---
# wine (ejecucion de .exe) + xvfb (display headless) + visor PDF vulnerable.
apt-get install -y --no-install-recommends \
    xvfb \
    "$VULN_APP" \
    wine \
    wine64 \
    2>&1 | tail -30

# Fallback: en algunas imagenes el metapaquete es 'wine-stable' o 'wine1.6'
command -v wine >/dev/null 2>&1 || apt-get install -y --no-install-recommends wine-stable wine1.6 2>&1 | tail -10

# --- Reporte de lo instalado (queda en la imagen para verificar) ---
{
  echo "provisioned_utc=$(date -u +%FT%TZ)"
  echo "wine=$(command -v wine || echo MISSING)"
  echo "xvfb=$(command -v Xvfb || echo MISSING)"
  echo "vuln_app=$VULN_APP:$(command -v $VULN_APP || echo MISSING)"
  echo -n "vuln_app_version="; ($VULN_APP -v 2>&1 || dpkg -s "$VULN_APP" 2>/dev/null | grep -i ^Version) | head -1
} > /root/.provisioned

# Limpieza para achicar la imagen
apt-get clean
rm -rf /var/lib/apt/lists/*

sync
echo "[provision] completo. Apagando (imagen base lista)."
sleep 1
poweroff -f 2>/dev/null || reboot -f
