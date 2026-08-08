"""
Preprocesador de Datos — DDoS Guardian
Combina CSV-01-12 (ataques) y CSV-03-11 (ataques + BENIGNO),
limpia errores y genera un CSV balanceado listo para entrenar.

Uso:
    python preprocesador.py
"""

import pandas as pd
import numpy as np
import os
import time

# ─── Configuración ────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Ajusta estas rutas a donde tengas las carpetas descargadas
FOLDER_01_12 = os.path.join(BASE_DIR, "../data/CSV-01-12")
FOLDER_03_11 = os.path.join(BASE_DIR, "../data/CSV-03-11/03-11")
OUTPUT_FILE  = os.path.join(BASE_DIR, "../data/CICDDoS2019_cleaned.csv")

CHUNK_SIZE      = 500_000
REFILL_RATE_PPS = 100.0

# Archivos a ignorar (locks, temporales, etc.)
SKIP_FILES = {".~lock.udplag.csv#"}

# ─── Mapeo de Columnas ────────────────────────────────────────
COL_MAP = {
    "flow packets/s":              "pps",
    "flow bytes/s":                "bps",
    "flow iat mean":               "mean_iat_ms",
    "syn flag count":              "syn_ratio",
    "total length of fwd packets": "pkt_count",
}

FEATURE_COLS = [
    "pps", "bps", "mean_iat_ms", "syn_ratio",
    "udp_ratio", "icmp_ratio", "pkt_count", "unique_dports", "tb_drop_ratio"
]


# ─── Helpers ──────────────────────────────────────────────────
def get_csv_files(folder: str) -> list[str]:
    """Devuelve todos los CSV válidos de una carpeta."""
    if not os.path.isdir(folder):
        print(f"[!] Carpeta no encontrada, se omite: {folder}")
        return []
    files = [
        os.path.join(folder, f)
        for f in sorted(os.listdir(folder))
        if f.lower().endswith(".csv") and f.lower() not in SKIP_FILES
    ]
    print(f"[*] {os.path.basename(folder)}: {len(files)} archivo(s) encontrado(s)")
    for f in files:
        size_mb = os.path.getsize(f) / 1024 / 1024
        print(f"    • {os.path.basename(f):35s} {size_mb:8.1f} MB")
    return files


def procesar_chunk(chunk: pd.DataFrame) -> pd.DataFrame | None:
    """Limpia y transforma un fragmento del CSV."""

    # 1. Normalizar nombres de columnas
    chunk.columns = chunk.columns.str.strip().str.lower()

    # 2. Renombrar a nuestro estándar
    chunk.rename(columns=COL_MAP, inplace=True)

    # Cálculo real de proporciones por protocolo si la columna existe
    if "protocol" in chunk.columns:
        chunk["udp_ratio"] = (chunk["protocol"] == 17).astype(float)
        chunk["icmp_ratio"] = ((chunk["protocol"] == 1) | (chunk["protocol"] == 58)).astype(float)
    else:
        if "udp length" in chunk.columns:
            chunk["udp_ratio"] = chunk["udp length"]
        if "fwd iat mean" in chunk.columns:
            chunk["icmp_ratio"] = chunk["fwd iat mean"]

    # 3. Etiquetado binario
    if "label" in chunk.columns:
        chunk["label"] = (
            chunk["label"].astype(str).str.strip().str.upper() != "BENIGN"
        ).astype(int)
    else:
        chunk["label"] = 1  # Si no hay label asumimos ataque (CSV-01-12)

    # 4. Asegurar que existan todas las features
    for col in FEATURE_COLS:
        if col not in chunk.columns:
            if col == "unique_dports":
                chunk[col] = 1.0
            else:
                chunk[col] = 0.0

    # 5. Convertir conteos a ratios (0.0–1.0)
    for col in ["syn_ratio", "udp_ratio", "icmp_ratio"]:
        if chunk[col].max() > 1.0:
            chunk[col] = (chunk[col] / chunk["pkt_count"].replace(0, 1)).clip(0, 1)

    # 6. Simular Token Bucket
    chunk["tb_drop_ratio"] = 0.0
    mask = chunk["pps"] > REFILL_RATE_PPS
    chunk.loc[mask, "tb_drop_ratio"] = (
        (chunk.loc[mask, "pps"] - REFILL_RATE_PPS) / chunk.loc[mask, "pps"]
    ).clip(0.0, 1.0)

    # 7. Seleccionar columnas finales
    chunk = chunk[FEATURE_COLS + ["label"]].copy()

    # 8. Eliminar infinitos y NaNs
    chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
    chunk.dropna(inplace=True)

    return chunk if len(chunk) > 0 else None


# ─── Main ─────────────────────────────────────────────────────
def procesar_todo():
    print("=" * 60)
    print("  DDoS Guardian — Preprocesador de Datos")
    print("=" * 60)
    start_time = time.time()

    # Recopilar todos los archivos de ambas carpetas
    all_files = get_csv_files(FOLDER_01_12) + get_csv_files(FOLDER_03_11)

    if not all_files:
        print("[✗] No se encontraron archivos CSV. Revisa las rutas.")
        return

    print(f"\n[*] Total: {len(all_files)} archivo(s) a procesar\n")

    # Limpiar salida anterior
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    first_chunk   = True
    total_crudas  = 0
    total_validas = 0
    total_ataques = 0
    total_benign  = 0

    for filepath in all_files:
        nombre = os.path.basename(filepath)
        print(f"[→] Procesando: {nombre}")
        file_rows = 0
        file_valid = 0

        try:
            for chunk in pd.read_csv(filepath, chunksize=CHUNK_SIZE, low_memory=False):
                total_crudas += len(chunk)
                file_rows    += len(chunk)

                resultado = procesar_chunk(chunk)
                if resultado is None:
                    continue

                file_valid    += len(resultado)
                total_validas += len(resultado)
                total_ataques += resultado["label"].sum()
                total_benign  += (resultado["label"] == 0).sum()

                resultado.to_csv(OUTPUT_FILE, mode="a", header=first_chunk, index=False)
                first_chunk = False

        except Exception as e:
            print(f"    [!] Error en {nombre}: {e}")
            continue

        print(f"    ✓ {file_rows:>10,} filas crudas → {file_valid:>10,} válidas")

    # ─── Resumen final ────────────────────────────────────────
    elapsed = time.time() - start_time
    ratio   = (total_benign / max(total_validas, 1)) * 100

    print("\n" + "=" * 60)
    print(f"  ✓ Proceso terminado en {elapsed:.1f} s")
    print(f"  Filas crudas  : {total_crudas:>12,}")
    print(f"  Filas válidas : {total_validas:>12,}")
    print(f"  ├─ Benigno    : {total_benign:>12,}  ({ratio:.1f}%)")
    print(f"  └─ Ataque     : {total_ataques:>12,}  ({100-ratio:.1f}%)")
    print(f"  Archivo listo : {OUTPUT_FILE}")
    print("=" * 60)

    if ratio < 5:
        print("\n[⚠] Advertencia: menos del 5% de tráfico benigno.")
        print("    Considera añadir más archivos con label BENIGN.")
    else:
        print("\n[✓] Balance aceptable — listo para entrenar con train.py")


if __name__ == "__main__":
    procesar_todo()