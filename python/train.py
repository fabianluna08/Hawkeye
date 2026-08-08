# python/train.py
"""
Entrena XGBoost sobre el dataset CICDDoS2019.
Incluye tb_drop_ratio como feature extra:
    - Si el Token Bucket ya rechazó paquetes de esa IP → señal fuerte de ataque.

Instalar:
    pip install xgboost scikit-learn pandas

Uso:
    python train.py
    → genera: modelo.json  y  model_meta.json
"""

import json
import os
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
import warnings
warnings.filterwarnings("ignore")

# ─── Configuración ────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_CSV  = os.path.join(BASE_DIR, "../data/CICDDoS2019_cleaned.csv")
MODEL_OUTPUT = os.path.join(BASE_DIR, "../modelo.json")
BASE_MODEL_OUTPUT = os.path.join(BASE_DIR, "../modelo_base.json")
META_OUTPUT  = os.path.join(BASE_DIR, "../model_meta.json")

# IMPORTANTE: mismo orden que out[] en stats_to_features() de predictor.cpp
FEATURE_COLS = [
    "pps",            # feat[0] — Paquetes por segundo
    "bps",            # feat[1] — Bytes por segundo
    "mean_iat_ms",    # feat[2] — Inter-arrival time medio (ms)
    "syn_ratio",      # feat[3] — Proporción de paquetes SYN
    "udp_ratio",      # feat[4] — Proporción UDP
    "icmp_ratio",     # feat[5] — Proporción ICMP
    "pkt_count",      # feat[6] — Total paquetes en ventana
    "unique_dports",  # feat[7] — Puertos destino únicos (popcount de un bitmap de 64 bits, ver xdp_kern.c)
    "tb_drop_ratio",  # feat[8] — Proporción de drops por Token Bucket
]
LABEL_COL = "label"  # 0 = benigno, 1 = ataque


# ─── Carga y mapeo del dataset ────────────────────────────────
def load_data(path: str) -> pd.DataFrame:
    print(f"[*] Cargando {path}…")
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

    # CICDDoS2019: columna 'label' tiene cadenas como 'BENIGN', 'DrDoS_UDP'.
    # is_numeric_dtype (en vez de comparar contra dtype==object) cubre tanto el
    # 'object' clásico de pandas como el dtype 'string' que algunas versiones
    # recientes de pandas usan por defecto para columnas de texto.
    if LABEL_COL in df.columns and not pd.api.types.is_numeric_dtype(df[LABEL_COL]):
        df[LABEL_COL] = (df[LABEL_COL] != "BENIGN").astype(int)

    # Mapear columnas del CSV a nuestras features
    col_map = {
        "flow_packets/s":                  "pps",
        "flow_bytes/s":                    "bps",
        "flow_iat_mean":                   "mean_iat_ms",
        "syn_flag_count":                  "syn_ratio",
        "total_length_of_fwd_packets":     "pkt_count",
    }
    for orig, new in col_map.items():
        if orig in df.columns:
            df.rename(columns={orig: new}, inplace=True)

    # Cálculo real de proporciones por protocolo si la columna existe
    if "protocol" in df.columns:
        df["udp_ratio"] = (df["protocol"] == 17).astype(float)
        df["icmp_ratio"] = ((df["protocol"] == 1) | (df["protocol"] == 58)).astype(float)
    else:
        if "udp_length" in df.columns:
            df.rename(columns={"udp_length": "udp_ratio"}, inplace=True)
        if "fwd_iat_mean" in df.columns and "icmp_ratio" not in df.columns:
            df.rename(columns={"fwd_iat_mean": "icmp_ratio"}, inplace=True)

    # tb_drop_ratio no existe en el dataset público → simularlo:
    if "tb_drop_ratio" not in df.columns:
        REFILL_RATE = 100.0
        df["tb_drop_ratio"] = 0.0
        mask = df["pps"] > REFILL_RATE
        df.loc[mask, "tb_drop_ratio"] = (
            (df.loc[mask, "pps"] - REFILL_RATE) / df.loc[mask, "pps"]
        ).clip(0.0, 1.0)

    # El dataset público CICDDoS2019 no trae conteo de puertos destino únicos por
    # flujo (no hay captura cruda disponible para reconstruirlo). Se rellena con 1.0
    # como placeholder neutro; las muestras sintéticas de abajo sí varían este valor
    # para que el modelo aprenda la señal real de escaneo de puertos.
    if "unique_dports" not in df.columns:
        df["unique_dports"] = 1.0

    # Normalizar ratios (si son conteos brutos, dividir por pkt_count)
    for col in ["syn_ratio", "udp_ratio", "icmp_ratio"]:
        if col in df.columns and df[col].max() > 1.0:
            df[col] = (df[col] / df["pkt_count"].replace(0, 1)).clip(0, 1)

    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0.0

    df = df[FEATURE_COLS + [LABEL_COL]].copy()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # --- INYECCIÓN DE ATAQUES SUTILES (Muestras tipo Mirai/Spoofing distribuidas) ---
    # Queremos que el modelo aprenda a detectar ataques sutiles que no activan el Token Bucket (tb_drop_ratio = 0)
    print("[*] Inyectando muestras sintéticas de ataques sutiles (tipo Mirai/Spoofing)...")
    num_synthetic = 5000
    
    # Generar muestras sintéticas de ataque UDP/SYN distribuido
    syn_attacks = pd.DataFrame({
        "pps": np.random.uniform(15, 80, num_synthetic),
        "bps": np.random.uniform(5000, 40000, num_synthetic),
        "mean_iat_ms": np.random.uniform(10, 60, num_synthetic),
        "syn_ratio": np.random.uniform(0.9, 1.0, num_synthetic),
        "udp_ratio": np.zeros(num_synthetic),
        "icmp_ratio": np.zeros(num_synthetic),
        "pkt_count": np.random.uniform(20, 150, num_synthetic),
        "unique_dports": np.random.choice([1, 2], num_synthetic),
        "tb_drop_ratio": np.zeros(num_synthetic),  # 0.0 drop ratio -> elude Capa 1
        "label": np.ones(num_synthetic, dtype=int)
    })

    udp_attacks = pd.DataFrame({
        "pps": np.random.uniform(15, 80, num_synthetic),
        "bps": np.random.uniform(8000, 60000, num_synthetic),
        "mean_iat_ms": np.random.uniform(10, 60, num_synthetic),
        "syn_ratio": np.zeros(num_synthetic),
        "udp_ratio": np.random.uniform(0.9, 1.0, num_synthetic),
        "icmp_ratio": np.zeros(num_synthetic),
        "pkt_count": np.random.uniform(20, 150, num_synthetic),
        "unique_dports": np.random.choice([1, 2], num_synthetic),
        "tb_drop_ratio": np.zeros(num_synthetic),  # 0.0 drop ratio
        "label": np.ones(num_synthetic, dtype=int)
    })

    # Escaneo de puertos: pocos paquetes por puerto pero muchos puertos destino
    # distintos (popcount alto del bitmap de 64 bits) — antes el modelo nunca veía
    # variación real en esta feature y no podía aprender esta señal.
    port_scan_attacks = pd.DataFrame({
        "pps": np.random.uniform(20, 100, num_synthetic),
        "bps": np.random.uniform(2000, 15000, num_synthetic),
        "mean_iat_ms": np.random.uniform(5, 50, num_synthetic),
        "syn_ratio": np.random.uniform(0.7, 1.0, num_synthetic),
        "udp_ratio": np.zeros(num_synthetic),
        "icmp_ratio": np.zeros(num_synthetic),
        "pkt_count": np.random.uniform(20, 150, num_synthetic),
        "unique_dports": np.random.uniform(15, 64, num_synthetic),
        "tb_drop_ratio": np.zeros(num_synthetic),
        "label": np.ones(num_synthetic, dtype=int)
    })

    # Tráfico benigno multi-servicio (ej. web + API + DNS): toca un puñado de
    # puertos distintos, para que el modelo no confunda "más de 1 puerto" con ataque.
    benign_multiport = pd.DataFrame({
        "pps": np.random.uniform(1, 20, num_synthetic),
        "bps": np.random.uniform(500, 8000, num_synthetic),
        "mean_iat_ms": np.random.uniform(50, 500, num_synthetic),
        "syn_ratio": np.random.uniform(0.0, 0.3, num_synthetic),
        "udp_ratio": np.random.uniform(0.0, 0.3, num_synthetic),
        "icmp_ratio": np.zeros(num_synthetic),
        "pkt_count": np.random.uniform(5, 50, num_synthetic),
        "unique_dports": np.random.uniform(1, 6, num_synthetic),
        "tb_drop_ratio": np.zeros(num_synthetic),
        "label": np.zeros(num_synthetic, dtype=int)
    })

    df = pd.concat([df, syn_attacks, udp_attacks, port_scan_attacks, benign_multiport], ignore_index=True)

    print(f"    Filas totales: {len(df):,}  |  Ataques: {df[LABEL_COL].sum():,}  "
          f"({df[LABEL_COL].mean()*100:.1f}%)")
    return df


# ─── Balanceo: Undersample de ataques ────────────────────────
def balance_data(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """
    Mantiene TODOS los ejemplos benignos (~17k) y
    muestrea aleatoriamente la misma cantidad de ataques → 50/50.

    Si quieres 60/40 cambia el multiplicador:
        n=int(len(df_normal) * 1.5)   → 60% ataques / 40% normal
    """
    print("[*] Balanceando dataset (undersample ataques 50/50)…")

    df_normal = df[df[LABEL_COL] == 0]
    df_attack = df[df[LABEL_COL] == 1].sample(
        n=len(df_normal),
        random_state=42
    )

    df_bal = pd.concat([df_normal, df_attack]).sample(frac=1, random_state=42)

    print(f"    Normal : {len(df_normal):,}")
    print(f"    Ataques: {len(df_attack):,}")
    print(f"    Total  : {len(df_bal):,}")

    X = df_bal[FEATURE_COLS].values.astype(np.float32)
    y = df_bal[LABEL_COL].values.astype(int)
    return X, y


# ─── Entrenamiento ────────────────────────────────────────────
def train(df: pd.DataFrame):
    X, y = balance_data(df)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y)

    dtrain = xgb.DMatrix(X_tr, label=y_tr, feature_names=FEATURE_COLS)
    dtest  = xgb.DMatrix(X_te, label=y_te, feature_names=FEATURE_COLS)

    params = {
        "objective":        "binary:logistic",
        "eval_metric":      ["logloss", "auc"],
        "max_depth":        6,
        "eta":              0.1,
        "subsample":        0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 5,
        "tree_method":      "hist",
        "device":           "cpu",
        "seed":             42,
    }

    print("[*] Entrenando XGBoost…")
    evals_result = {}
    model = xgb.train(
        params, dtrain,
        num_boost_round=300,
        evals=[(dtrain, "train"), (dtest, "test")],
        early_stopping_rounds=20,
        evals_result=evals_result,
        verbose_eval=50,
    )

    # ── Evaluación ──────────────────────────────────────────────
    y_prob = model.predict(dtest)
    y_pred = (y_prob >= 0.5).astype(int)

    print("\n── Reporte de clasificación ──")
    print(classification_report(y_te, y_pred, target_names=["Benigno", "Ataque"]))
    print(f"AUC-ROC : {roc_auc_score(y_te, y_prob):.4f}")
    print("Confusión:")
    print(confusion_matrix(y_te, y_pred))

    # ── Guardar modelo en JSON (estándar XGBoost ≥ 2.0) ─────────
    model.save_model(MODEL_OUTPUT)
    model.save_model(BASE_MODEL_OUTPUT)
    print(f"\n[✓] Modelo guardado → {MODEL_OUTPUT}")
    print(f"[✓] Modelo base (ancla) guardado → {BASE_MODEL_OUTPUT}")

    # ── Metadata para el agente Python ──────────────────────────
    meta = {
        "feature_names":  FEATURE_COLS,
        "n_features":     len(FEATURE_COLS),
        "threshold":      0.5,
        "best_iteration": model.best_iteration,
        "best_auc":       float(max(evals_result["test"]["auc"])),
    }
    with open(META_OUTPUT, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[✓] Metadata guardada → {META_OUTPUT}")
    return model


if __name__ == "__main__":
    df = load_data(DATASET_CSV)
    train(df)