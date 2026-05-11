"""
routers/parametres_correlation.py
GET/PUT /api/parametres-correlation/config      → config.yml
GET/PUT /api/parametres-correlation/vuln-types  → vulns_types.yml
"""

import yaml
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/parametres-correlation", tags=["Paramètres Corrélation"])

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
CONFIG_PATH = SCRIPTS_DIR / "config.yml"
VULN_TYPES_PATH = SCRIPTS_DIR / "vulns_types.yml"


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Fichier {path.name} introuvable")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _write_yaml(path: Path, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


# ── Config.yml ────────────────────────────────────────────────────────

@router.get("/config")
def get_config():
    return _read_yaml(CONFIG_PATH)


@router.put("/config")
def put_config(body: dict):
    # Validation minimale des clés attendues
    required = {"correlation", "mistral", "rapport"}
    missing = required - body.keys()
    if missing:
        raise HTTPException(status_code=422, detail=f"Sections manquantes : {missing}")
    _write_yaml(CONFIG_PATH, body)
    return {"ok": True}


# ── vuln_types.yml ────────────────────────────────────────────────────

@router.get("/vuln-types")
def get_vuln_types():
    return _read_yaml(VULN_TYPES_PATH)


@router.put("/vuln-types")
def put_vuln_types(body: dict):
    if "types" not in body:
        raise HTTPException(status_code=422, detail="Clé 'types' manquante")
    _write_yaml(VULN_TYPES_PATH, body)
    return {"ok": True}