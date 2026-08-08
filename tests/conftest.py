"""Fixtures compartidas para los tests de HawkEye IDS.

Estrategia: python/api.py hace todo su setup (DB, seed, migraciones) al importarse,
así que la fixture `api_module` prepara el entorno (variables, cwd temporal para que
hawkeye.db no ensucie el repo, y un stub del módulo `agent` para no cargar la pila
pesada de LangChain/SHAP/ChromaDB) ANTES de importar `api`.
"""

import os
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON_DIR = REPO_ROOT / "python"

TEST_EDGE_TOKEN = "token-de-servicio-edge-solo-para-tests"
ADMIN_EMAIL = "admin@hawkeye.local"
ADMIN_PASSWORD = "password-de-test-123"


@pytest.fixture(scope="session")
def api_module(tmp_path_factory):
    # api.py exige HAWKEYE_API_TOKEN al importarse
    os.environ["HAWKEYE_API_TOKEN"] = TEST_EDGE_TOKEN

    # La DB se crea relativa al cwd ("sqlite:///./hawkeye.db"): usamos un dir temporal
    tmp = tmp_path_factory.mktemp("hawkeye_test_db")
    old_cwd = os.getcwd()
    os.chdir(tmp)

    # Stub de `agent` para que /api/alertas funcione sin cargar LangChain/SHAP/ChromaDB
    agent_stub = types.ModuleType("agent")
    agent_stub.explain_alert = lambda alert: {"shap_ranking": []}
    sys.modules["agent"] = agent_stub

    if str(PYTHON_DIR) not in sys.path:
        sys.path.insert(0, str(PYTHON_DIR))

    import api  # noqa: E402  (dispara create_all + migraciones + seed)

    yield api

    os.chdir(old_cwd)


@pytest.fixture(scope="session")
def admin_credentials(api_module):
    """Fija credenciales conocidas (password + secreto TOTP) para el admin sembrado."""
    import pyotp

    totp_secret = pyotp.random_base32()
    db = api_module.SessionLocal()
    user = db.query(api_module.DbUser).filter(api_module.DbUser.email == ADMIN_EMAIL).first()
    assert user is not None, "seed_db debería haber creado el admin"
    user.password = api_module.hash_password(ADMIN_PASSWORD)
    user.totp_secret = totp_secret
    db.commit()
    db.close()
    return {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "totp_secret": totp_secret}


@pytest.fixture(scope="session")
def client(api_module):
    from fastapi.testclient import TestClient

    with TestClient(api_module.app) as c:
        yield c
