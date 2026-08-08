"""Valida el contrato de features del modelo entre model_meta.json, src/predictor.cpp
y python/train.py, para evitar que se repita la inconsistencia 8 vs 9 features.

El orden es contractual: predictor.cpp construye el vector feat[] por índice y el
modelo XGBoost fue entrenado con FEATURE_COLS en ese mismo orden.
"""

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Orden canónico según src/predictor.cpp (stats_to_features / N_FEATURES = 9)
EXPECTED_FEATURES = [
    "pps",
    "bps",
    "mean_iat_ms",
    "syn_ratio",
    "udp_ratio",
    "icmp_ratio",
    "pkt_count",
    "unique_dports",
    "tb_drop_ratio",
]


def test_model_meta_tiene_9_features_en_orden():
    meta = json.loads((REPO_ROOT / "model_meta.json").read_text())
    assert len(meta["feature_names"]) == 9
    assert meta["feature_names"] == EXPECTED_FEATURES
    if "n_features" in meta:
        assert meta["n_features"] == 9


def test_predictor_cpp_declara_9_features():
    src = (REPO_ROOT / "src" / "predictor.cpp").read_text()
    m = re.search(r"N_FEATURES\s*=\s*(\d+)", src)
    assert m, "no se encontró N_FEATURES en predictor.cpp"
    assert int(m.group(1)) == 9


def test_predictor_cpp_emite_features_con_mismo_orden_e_indices():
    """predictor.cpp serializa la alerta JSON como R"("<nombre>":)" << feat[<i>]:
    extraemos esos pares y validamos nombre e índice contra el orden canónico."""
    src = (REPO_ROOT / "src" / "predictor.cpp").read_text()
    pares = re.findall(r'R"\("(\w+)":\)"\s*<<\s*feat\[(\d+)\]', src)
    assert pares, "no se encontró la serialización de features en predictor.cpp"
    mapping = {nombre: int(idx) for nombre, idx in pares}
    assert mapping == {nombre: i for i, nombre in enumerate(EXPECTED_FEATURES)}


def test_train_py_usa_el_mismo_orden():
    src = (REPO_ROOT / "python" / "train.py").read_text()
    # El cierre "]" de la lista está al inicio de línea (los comentarios internos
    # contienen "]" en "feat[i]", por eso no se puede cortar en el primer "]").
    m = re.search(r"FEATURE_COLS\s*=\s*\[(.*?)^\]", src, re.DOTALL | re.MULTILINE)
    assert m, "no se encontró FEATURE_COLS en train.py"
    # Solo los nombres entre comillas al inicio de cada ítem (no texto de comentarios)
    cols = re.findall(r'^\s*"(\w+)"', m.group(1), re.MULTILINE)
    assert cols == EXPECTED_FEATURES
