# HawkEye — DDoS Guardian + Mictlan Secure Sandbox 🛡️🦅

Versión simplificada de HawkEye: solo las dos capas independientes que se
pueden compilar y correr sin el resto de la plataforma (CASCADA-4, el
dashboard web y el agente cognitivo con LangChain/SHAP no están en este
repo).

fabianluna981@gmail.com
ana.cristinajp0525@gmail.com
ricoguerrerox@gmail.com

## Capa 1-2 — Detección y mitigación DDoS a velocidad de hardware

* **`kern/xdp_kern.c`**: programa eBPF/XDP que filtra paquetes *antes* de que
  el kernel asigne un `sk_buff`, con un token bucket por IP en un mapa LRU.
  (También redirige tráfico de puertos 80/443/445 a una cola AF_XDP para un
  pipeline de inspección profunda que no forma parte de este repo — el
  redirect existe en el código pero no hay consumidor aquí.)
* **`src/predictor.cpp`**: demonio en C++ (libbpf CO-RE) que lee los mapas
  eBPF cada 200 ms, arma un vector de 9 características por IP y corre
  inferencia XGBoost para decidir bloqueo proactivo.
* **`python/train.py`**: entrena el modelo sobre el dataset público
  [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html) (no incluido
  por tamaño — instrucciones abajo) y genera `modelo.json` / `modelo_base.json`
  / `model_meta.json`.
* **`python/online_trainer.py`** + **`python/preprocesador.py`**: reentrenamiento
  incremental con muestras reales capturadas por el predictor
  (`training_samples.jsonl`), con rollback al modelo base ancla si el
  reentrenamiento empeora las métricas.
* `modelo.json`, `modelo_base.json`, `model_meta.json`: pesos ya entrenados,
  listos para usar con `predictor`.

### Compilar y correr

```bash
make install-deps      # clang, libbpf-dev, bpftool, cmake... (Ubuntu/Debian)
make                    # vmlinux.h + xdp_kern.o + build/predictor
sudo ./build/predictor eth0 modelo.json
```

Para reentrenar desde cero, descarga `CICDDoS2019_cleaned.csv` (columnas
compatibles con CIC-DDoS2019) en `data/` y corre:

```bash
pip install -r python/requirements.txt
python3 python/train.py
```

## Capa 5 — Mictlan Secure Sandbox

Cuarentena y detonación aislada de payloads sospechosos en microVMs
Firecracker air-gapped, con supervisión eBPF anti-escape desde el host.

* **`mictlan/orchestrator.py`**: orquesta el ciclo de vida de la microVM
  (clona el rootfs base en un disco COW efímero, inyecta el payload sin red
  vía `debugfs`, arranca, detona, extrae telemetría, destruye el disco).
* **`mictlan/guest_inject.py`** / **`guest_runtime.py`**: manipulación
  rootless del `ext4` del guest y runtime de arranque.
* **`mictlan/static_analysis.py`**: filtrado pre-ejecución y clasificación
  con reglas YARA (`mictlan/rules/malware.yar`).
* **`mictlan/monitor.py`** + **`mictlan/bpf/sandbox_monitor.c`**: sonda eBPF
  en el host sobre `sys_enter_execve` para detectar intentos de escape,
  invisible para el proceso confinado.
* **`mictlan/l7_capture/`**: captura y correlación L7 opcional del tráfico
  de detonación (pensada para cruzar contra la reputación del IDS completo,
  no incluido aquí).
* **`mictlan/guest_assets/`**: scripts de aprovisionamiento y detonación que
  corren *dentro* del guest air-gapped.

Ver `mictlan/README.md` para el detalle completo de la arquitectura del
sandbox.

### Uso

```bash
python3 -m venv mictlan/venv && mictlan/venv/bin/pip install -r mictlan/requirements.txt
sudo mictlan/setup_firecracker.sh        # descarga firecracker + kernel/rootfs base
sudo mictlan/setup_rootfs_wine.sh        # (opcional) aprovisiona Wine/Xvfb/visor señuelo
python3 mictlan/orchestrator.py /ruta/al/payload_sospechoso.exe
```

`mictlan/vm_data/` (imágenes base ~300MB+) no está versionado — lo genera
`setup_firecracker.sh`.

## Qué no está en este repo

Este es un recorte deliberado del monorepo original de HawkEye. Quedan
fuera: CASCADA-4 (inspección JA4/JA4T, reensamblado TCP, parsers HTTP/SMB2,
detección DGA/DNS), el agente cognitivo (LangChain + SHAP), la API REST/WS
(FastAPI) y el dashboard web. Esas piezas están fuertemente acopladas entre
sí y no tenían sentido sueltas en una versión simplificada.

## Licencia

MIT — ver `LICENSE`.
