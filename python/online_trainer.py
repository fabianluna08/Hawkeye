#!/usr/bin/env python3
"""
Módulo de Entrenamiento Continuo e Incremental — DDoS Guardian
Permite que el modelo XGBoost aprenda continuamente de nuevos flujos o alertas confirmadas
sin sufrir olvido catastrófico (catastrophic forgetting), conservando un modelo base ancla (modelo_base.json).

Uso independiente:
    python online_trainer.py --samples nuevos_datos.csv
    python online_trainer.py --from-alerts
    python online_trainer.py --rollback
"""

import os
import json
import shutil
import argparse
import pandas as pd
import numpy as np
import xgboost as xgb

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "../modelo.json")
BASE_MODEL_PATH = os.path.join(BASE_DIR, "../modelo_base.json")
META_PATH = os.path.join(BASE_DIR, "../model_meta.json")
DATASET_CSV = os.path.join(BASE_DIR, "../data/CICDDoS2019_cleaned.csv")
ALERTS_PATH = os.path.join(BASE_DIR, "../alerts.jsonl")
CAPTURE_PATH = os.path.join(BASE_DIR, "../training_samples.jsonl")

FEATURE_COLS = [
    "pps", "bps", "mean_iat_ms", "syn_ratio",
    "udp_ratio", "icmp_ratio", "pkt_count", "unique_dports", "tb_drop_ratio"
]
LABEL_COL = "label"

def ensure_base_model():
    """Verifica que exista el modelo base como ancla inmutable para reentrenamiento/rollback."""
    if not os.path.exists(BASE_MODEL_PATH):
        if os.path.exists(MODEL_PATH):
            shutil.copyfile(MODEL_PATH, BASE_MODEL_PATH)
            print(f"[+] Modelo base creado como ancla en: {BASE_MODEL_PATH}")
        else:
            raise FileNotFoundError("No existe modelo.json ni modelo_base.json. Ejecuta train.py primero.")

def rollback_to_base():
    """Restaura el modelo activo desde el modelo base ancla."""
    if not os.path.exists(BASE_MODEL_PATH):
        return False, "No existe un modelo_base.json para restaurar."
    shutil.copyfile(BASE_MODEL_PATH, MODEL_PATH)
    print(f"[✓] Rollback exitoso: modelo.json restaurado desde {BASE_MODEL_PATH}")
    return True, f"Modelo restaurado desde ancla base {BASE_MODEL_PATH}."

def load_replay_buffer(n_samples=500):
    """Carga una muestra aleatoria del dataset original para evitar olvido catastrófico."""
    if not os.path.exists(DATASET_CSV):
        return pd.DataFrame()
    try:
        df = pd.read_csv(DATASET_CSV, low_memory=False)
        if len(df) > n_samples:
            df = df.sample(n=n_samples, random_state=42)
        return df
    except Exception as e:
        print(f"[!] No se pudo cargar replay buffer: {e}")
        return pd.DataFrame()

def train_continuous(new_data_df: pd.DataFrame, num_boost_round=10):
    """
    Entrenamiento incremental sobre el modelo activo.
    Combina new_data_df con replay buffer del dataset base.
    """
    ensure_base_model()
    
    if new_data_df is None or len(new_data_df) == 0:
        return False, "No hay nuevos datos para entrenar."

    # Asegurar columnas necesarias en new_data_df
    for col in FEATURE_COLS:
        if col not in new_data_df.columns:
            new_data_df[col] = 0.0
    if LABEL_COL not in new_data_df.columns:
        new_data_df[LABEL_COL] = 1

    new_data_df = new_data_df[FEATURE_COLS + [LABEL_COL]].copy()
    new_data_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    new_data_df.dropna(inplace=True)

    if len(new_data_df) == 0:
        return False, "Los datos nuevos no contienen filas válidas."

    # Combinar con replay buffer
    replay_df = load_replay_buffer(n_samples=min(1000, max(200, len(new_data_df) * 2)))
    if len(replay_df) > 0:
        combined_df = pd.concat([replay_df, new_data_df], ignore_index=True)
    else:
        combined_df = new_data_df

    X = combined_df[FEATURE_COLS]
    y = combined_df[LABEL_COL]

    dtrain = xgb.DMatrix(X, label=y, feature_names=FEATURE_COLS)

    params = {
        "objective": "binary:logistic",
        "eval_metric": "auc",
        "max_depth": 6,
        "learning_rate": 0.05,
    }

    print(f"[*] Entrenando de forma continua ({num_boost_round} árboles adicionales) con {len(combined_df)} muestras...")
    
    model = xgb.train(
        params,
        dtrain,
        num_boost_round=num_boost_round,
        xgb_model=MODEL_PATH
    )

    model.save_model(MODEL_PATH)
    print(f"[✓] Modelo actualizado guardado en {MODEL_PATH}")

    if os.path.exists(META_PATH):
        try:
            with open(META_PATH, "r") as f:
                meta = json.load(f)
            meta["continuous_updates"] = meta.get("continuous_updates", 0) + 1
            meta["last_train_samples"] = len(new_data_df)
            with open(META_PATH, "w") as f:
                json.dump(meta, f, indent=2)
        except Exception:
            pass

    return True, f"Entrenamiento continuo exitoso (+{num_boost_round} árboles, {len(new_data_df)} nuevas muestras registradas)."

def train_from_alerts():
    """Convierte en dataset de fine-tuning solo las alertas que un analista confirmó
    explícitamente como 'Resuelta' desde el dashboard (campo "confirmado": true).
    No etiquetar automáticamente todo lo registrado evita envenenar el modelo con
    falsos positivos o tráfico diseñado para parecer un ataque."""
    if not os.path.exists(ALERTS_PATH):
        return False, "Archivo alerts.jsonl no encontrado."

    records = []
    with open(ALERTS_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if not data.get("confirmado"):
                    continue
                row = {col: float(data.get(col, 0.0)) for col in FEATURE_COLS}
                row[LABEL_COL] = 1
                records.append(row)
            except Exception:
                continue

    if not records:
        return False, "No hay alertas confirmadas por un analista en alerts.jsonl."
    
    df = pd.DataFrame(records)
    return train_continuous(df)

def train_from_capture():
    """Reentrena con training_samples.jsonl, generado por src/predictor.cpp
    cuando corre con HAWKEYE_CAPTURE_TRAINING_DATA=1 (ver CAMBIOS v5 en ese
    archivo). A diferencia de train_from_alerts() (que solo etiqueta
    ataques, label=1 fijo), acá el label ya viene en cada fila tal cual lo
    escribió el predictor: 0 (benigno, la mayoría del tráfico real
    capturado) o 1 (confirmado como bloqueo, o forzado con
    HAWKEYE_CAPTURE_LABEL durante una ventana de ataque controlado). Esto es
    lo que realmente corrige el sesgo del dataset original (CICDDoS2019 +
    sintético), que no tiene tráfico benigno real."""
    if not os.path.exists(CAPTURE_PATH):
        return False, "Archivo training_samples.jsonl no encontrado (¿corriste el predictor con HAWKEYE_CAPTURE_TRAINING_DATA=1?)."

    records = []
    with open(CAPTURE_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                row = {col: float(data.get(col, 0.0)) for col in FEATURE_COLS}
                row[LABEL_COL] = int(data.get("label", 0))
                records.append(row)
            except Exception:
                continue

    if not records:
        return False, "training_samples.jsonl no tiene filas válidas."

    df = pd.DataFrame(records)
    n_benign = int((df[LABEL_COL] == 0).sum())
    n_attack = int((df[LABEL_COL] == 1).sum())
    success, msg = train_continuous(df)
    if success:
        msg += f" (capturadas: {n_benign} benignas, {n_attack} ataque)"
    return success, msg

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS Guardian — Online Continuous Trainer")
    parser.add_argument("--from-alerts", action="store_true", help="Entrenar con alertas recientes de alerts.jsonl")
    parser.add_argument("--from-capture", action="store_true", help="Entrenar con training_samples.jsonl (captura real benigna+ataque de predictor.cpp)")
    parser.add_argument("--rollback", action="store_true", help="Restaurar el modelo desde el ancla base (modelo_base.json)")
    parser.add_argument("--samples", type=str, help="Ruta a un CSV de nuevas muestras para fine-tuning")

    args = parser.parse_args()
    if args.rollback:
        success, msg = rollback_to_base()
        print(msg)
    elif getattr(args, "from_alerts", False):
        success, msg = train_from_alerts()
        print(msg)
    elif getattr(args, "from_capture", False):
        success, msg = train_from_capture()
        print(msg)
    elif args.samples:
        df = pd.read_csv(args.samples)
        success, msg = train_continuous(df)
        print(msg)
    else:
        parser.print_help()
