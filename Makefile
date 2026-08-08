# Makefile — HawkEye DDoS Guardian (núcleo simplificado)
#
# Comandos:
#   make            → todo (vmlinux + kern + userspace)
#   make vmlinux    → genera kern/vmlinux.h desde el kernel actual
#   make kern       → compila xdp_kern.o
#   make userspace  → compila predictor con CMake
#   make clean      → limpia artefactos
#   make detach IFACE=eth0 → desconecta el programa XDP de una interfaz

CLANG      ?= clang
ARCH       ?= x86
KERN_SRC    = kern/xdp_kern.c
KERN_OBJ    = xdp_kern.o
VMLINUX_H   = kern/vmlinux.h

BPF_CFLAGS  = -O2 -g -target bpf                       \
              -D__TARGET_ARCH_$(ARCH)                   \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -I/usr/include                             \
              -Ikern/

.PHONY: all vmlinux kern userspace clean install-deps detach

all: vmlinux kern userspace

## Genera vmlinux.h desde el kernel en ejecución (requiere BTF habilitado)
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@echo "[*] Generando $(VMLINUX_H) desde /sys/kernel/btf/vmlinux…"
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
	    echo "[!] ERROR: /sys/kernel/btf/vmlinux no existe."; \
	    echo "    Asegúrate de que tu kernel fue compilado con CONFIG_DEBUG_INFO_BTF=y"; \
	    exit 1; \
	fi
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)
	@echo "[✓] $(VMLINUX_H) generado"

## Compila el programa XDP
kern: $(KERN_OBJ)

$(KERN_OBJ): $(KERN_SRC) $(VMLINUX_H) kern/xdp_common.h
	@echo "[*] Compilando $(KERN_SRC)…"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[✓] $(KERN_OBJ) listo"

## Compila el predictor C++ con CMake
userspace:
	@echo "[*] Compilando predictor C++…"
	cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
	cmake --build build --parallel $(shell nproc)
	@echo "[✓] build/predictor listo"

## Instala dependencias del sistema (Ubuntu/Debian)
install-deps:
	@echo "[*] Instalando dependencias…"
	sudo apt-get update
	sudo apt-get install -y \
	    clang llvm \
	    libbpf-dev \
	    linux-tools-common linux-tools-generic \
	    bpftool \
	    cmake build-essential pkg-config \
	    libelf-dev zlib1g-dev
	@echo ""
	@echo "[!] XGBoost debe instalarse manualmente:"
	@echo "    https://xgboost.readthedocs.io/en/stable/install.html"
	@echo "    (descarga la release y cmake --install)"

clean:
	rm -f $(KERN_OBJ) $(VMLINUX_H)
	rm -rf build
	@echo "[✓] Limpio"

## Desconecta el programa XDP de una interfaz de red especificada (ej. make detach IFACE=eth0)
detach:
	@if [ -z "$(IFACE)" ]; then \
	    echo "[!] ERROR: Debes especificar la interfaz. Ej: make detach IFACE=eth0"; \
	    exit 1; \
	fi
	@echo "[*] Forzando desconexión de XDP en la interfaz $(IFACE)..."
	sudo ip link set dev $(IFACE) xdp off || sudo bpftool net detach xdp dev $(IFACE)
	@echo "[✓] XDP desconectado exitosamente"
