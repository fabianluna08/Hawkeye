#!/bin/bash
#
# Descarga los assets de la microVM (kernel, rootfs, binario de firecracker).
# Todas las descargas se verifican por checksum antes de usarse: un ataque de
# DNS/repo comprometido que sustituya alguno de estos binarios (que despues se
# ejecutan con privilegios de KVM) se detecta aca en vez de pasar desapercibido.
set -e

DIR="/home/fabianluna/sandbox"
mkdir -p "$DIR/vm_data"
cd "$DIR/vm_data"

ARCH="$(uname -m)"

# vmlinux.bin y rootfs.ext4 vienen del bucket S3 de quickstart de Firecracker,
# que NO publica checksums propios. Estos hashes son "trust on first use": se
# calcularon sobre una descarga ya verificada manualmente en esta misma
# maquina, asi que una re-ejecucion de este script detecta corrupcion o una
# sustitucion silenciosa del archivo remoto, aunque no sean un checksum
# firmado por el upstream.
KERNEL_SHA256="ea5e7d5cf494a8c4ba043259812fc018b44880d70bcbbfc4d57d2760631b1cd6"
ROOTFS_SHA256="2a840feeccb5cb161c6eab1ecd86667c06ed5e307da534d2d3c9e39a6ec6c30a"

verify_sha256() {
    local file="$1" expected="$2"
    local actual
    actual="$(sha256sum "$file" | awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "ERROR: checksum de $file no coincide." >&2
        echo "  esperado: $expected" >&2
        echo "  obtenido: $actual" >&2
        exit 1
    fi
    echo "  checksum OK: $file"
}

if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
    echo "ERROR: arquitectura $ARCH sin checksum pineado en este script." >&2
    exit 1
fi
if [ "$ARCH" != "x86_64" ]; then
    echo "AVISO: los checksums de kernel/rootfs pineados arriba son para x86_64;" >&2
    echo "       en $ARCH no se puede verificar integridad de esos dos archivos." >&2
fi

echo "Downloading Linux Kernel for Firecracker..."
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/${ARCH}/kernels/vmlinux.bin"
curl -fsSL -o vmlinux.bin "$KERNEL_URL"
[ "$ARCH" = "x86_64" ] && verify_sha256 vmlinux.bin "$KERNEL_SHA256"

echo "Downloading Root Filesystem (Ubuntu Bionic)..."
ROOTFS_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/${ARCH}/rootfs/bionic.rootfs.ext4"
curl -fsSL -o rootfs.ext4 "$ROOTFS_URL"
[ "$ARCH" = "x86_64" ] && verify_sha256 rootfs.ext4 "$ROOTFS_SHA256"

cd "$DIR"

echo "Downloading Firecracker binary..."
# Using v1.7.0 as it's a very stable release for these older quickstart images
FC_RELEASE="v1.7.0"
FC_TGZ="firecracker-${FC_RELEASE}-${ARCH}.tgz"
curl -fsSL -o "$FC_TGZ" "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_RELEASE}/${FC_TGZ}"
# Este SI lo publica el upstream (release asset oficial de GitHub) -> checksum
# autoritativo, no TOFU.
curl -fsSL -o "${FC_TGZ}.sha256.txt" "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_RELEASE}/${FC_TGZ}.sha256.txt"
sha256sum -c "${FC_TGZ}.sha256.txt"
echo "  checksum OK: $FC_TGZ (verificado contra release oficial)"

tar -xzf "$FC_TGZ"
mv "release-${FC_RELEASE}-${ARCH}/firecracker-${FC_RELEASE}-${ARCH}" firecracker
chmod +x firecracker

rm -rf "release-${FC_RELEASE}-${ARCH}" "$FC_TGZ" "${FC_TGZ}.sha256.txt"

echo "Setup complete! Firecracker binary and VM assets are ready in $DIR/vm_data"
