#!/usr/bin/env python3
import sys
import os

# Résolution du projet root depuis le chemin réel du script
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from database import get_connection
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from mistralai.client.sdk import Mistral
import pymysql
import typer
from dotenv import load_dotenv
from typing import Optional
from datetime import datetime
import collections
import functools
import re
import time
import logging
import yaml
import json
from pathlib import Path

"""
correlate_and_analyze.py — Pipeline corrélation + analyse Mistral

Architecture en 3 phases :

PHASE 1 — Détection brute (SQL only, zéro IA)
  Passe unique vendor_match :
    - Match obligatoire : cve.fabricant == asset.nvd_vendor
    - Scoring version : tokens communs entre CVE et asset (version_os/firmware/bios/OS)
    - Bonus produit : +0.5 score si match produit suffisant (jamais bloquant)

PHASE 2 — Pré-classification déterministe (Python, zéro IA)
  Calcule score_pre_triage et priorite_pre_triage selon des règles objectives.

PHASE 3 — Validation Mistral (IA contextuelle)
  Mistral confirme/infirme et ajuste, ne score pas from scratch.
  Verdict : confirme | informatif | faux_positif

Usage:
  python correlate_and_analyze.py --help
  python correlate_and_analyze.py correlate
  python correlate_and_analyze.py analyze
  python correlate_and_analyze.py report --output-dir <BASE_DIR>/documents
  python correlate_and_analyze.py run-all
"""


BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv()

# ── Chargement de la config ──────────────────────────────────────────


def load_config():
    config_path = Path(__file__).resolve().parent / "config.yml"
    if not config_path.exists():
        return {}
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


CFG = load_config()


def load_vuln_types() -> dict:
    path = Path(__file__).resolve().parent / "vuln_types.yml"
    if not path.exists():
        print("⚠️  vuln_types.yml introuvable — tous les CVE passeront à Mistral")
        return {}
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("types", {})


VULN_TYPES = load_vuln_types()

CWE_TO_TYPE: dict[str, str] = {}
KEYWORDS_TO_TYPE: list[tuple[str, str]] = []
for _type_id, _type_def in VULN_TYPES.items():
    for _cwe in _type_def.get("cwe_ids", []):
        CWE_TO_TYPE[_cwe] = _type_id
    for _kw in _type_def.get("keywords", []):
        KEYWORDS_TO_TYPE.append((_kw.lower(), _type_id))


def cfg_corr(key, default):
    return CFG.get("correlation", {}).get(key, default)


def cfg_mistral(key, default):
    return CFG.get("mistral", {}).get(key, default)


def cfg_rapport(key, default):
    return CFG.get("rapport", {}).get(key, default)

# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════


MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY", "")
MISTRAL_MODEL = os.getenv("MISTRAL_MODEL") or cfg_mistral(
    "model", "mistral-large-latest")
MISTRAL_DELAY = float(os.getenv("MISTRAL_DELAY")
                      or cfg_mistral("delay_seconds", 1.5))
MISTRAL_BATCH_MAX = int(os.getenv("MISTRAL_BATCH_MAX")
                        or cfg_mistral("batch_max", 0))

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

print = functools.partial(print, flush=True)

app = typer.Typer(
    help="Pipeline corrélation CVE / analyse Mistral / rapport PDF")


# ═══════════════════════════════════════════════════════════════════════
# HELPERS BDD
# ═══════════════════════════════════════════════════════════════════════

def dict_cursor(conn):
    return conn.cursor(pymysql.cursors.DictCursor)


# ═══════════════════════════════════════════════════════════════════════
# COMPARAISON DE VERSIONS
# ═══════════════════════════════════════════════════════════════════════

def normalize_version(version_str):
    """Extrait les composants numériques d'une version. '5.4.0-1234' -> [5, 4, 0, 1234]"""
    if not version_str or version_str == "*":
        return []
    parts = re.findall(r'\d+', str(version_str))
    return [int(p) for p in parts]


def common_chars_count(s1, s2):
    """Compte les caractères alphanumériques communs entre deux chaînes (insensible à la casse)."""
    if not s1 or not s2:
        return 0

    def clean(s): return re.sub(r'[^a-z0-9]', '', str(s).lower())
    c1 = collections.Counter(clean(s1))
    c2 = collections.Counter(clean(s2))
    return sum((c1 & c2).values())


def product_matches_asset(cve_product, asset):
    """
    Vérifie si le produit NVD de la CVE correspond à l'asset.
    Règles :
      1. Match exact sur nvd_product du modèle de l'asset
      2. Sinon : 4+ caractères communs avec nvd_product ou systeme_exploitation
    """
    if not cve_product:
        return True  # Pas de produit → prudence

    cve_prod_clean = re.sub(r'[^a-z0-9]', '', cve_product.lower())

    nvd_product = asset.get("nvd_product") or ""
    if nvd_product and re.sub(r'[^a-z0-9]', '', nvd_product.lower()) == cve_prod_clean:
        return True
    min_chars = cfg_corr("product_match_min_chars", 6)
    if nvd_product and common_chars_count(cve_product, nvd_product) >= min_chars:
        return True

    os_text = asset.get("systeme_exploitation") or ""
    if os_text and common_chars_count(cve_product, os_text) >= min_chars:
        return True

    return False


def version_matches_asset(cve_versions_data, asset):
    """
    Vérifie qu'au moins une version CVE partage 4+ caractères avec une version asset.
    Si aucune version CVE ou asset connue → True (prudence).
    """
    if not cve_versions_data:
        return True

    cve_version_strings = []
    for v_range in cve_versions_data:
        for key in ("version_exact", "version_start_including",
                    "version_start_excluding", "version_end_including",
                    "version_end_excluding"):
            val = v_range.get(key)
            if val and val != "*":
                cve_version_strings.append(str(val))

    if not cve_version_strings:
        return True

    asset_versions_raw = [
        asset.get("version_os"),
        asset.get("version_firmware"),
        asset.get("version_bios"),
        asset.get("systeme_exploitation"),
    ]

    asset_versions = []
    for v in asset_versions_raw:
        if not v:
            continue
        asset_versions.append(v)
        tokens = re.findall(r'[a-zA-Z0-9]{3,}', str(v))
        asset_versions.extend(tokens)

    asset_versions = list(set(filter(None, asset_versions)))

    if not asset_versions:
        return True  # Pas de version asset connue → prudence

    min_chars = cfg_corr("version_match_min_chars", 4)
    for cve_ver in cve_version_strings:
        for asset_ver in asset_versions:
            if common_chars_count(cve_ver, asset_ver) >= min_chars:
                return True

    return False


def compare_versions(v1, v2):
    """-1 si v1 < v2, 0 si égales, 1 si v1 > v2"""
    v1_parts = normalize_version(v1)
    v2_parts = normalize_version(v2)
    for i in range(max(len(v1_parts), len(v2_parts))):
        p1 = v1_parts[i] if i < len(v1_parts) else 0
        p2 = v2_parts[i] if i < len(v2_parts) else 0
        if p1 < p2:
            return -1
        if p1 > p2:
            return 1
    return 0


def is_version_affected(asset_version, cve_version_ranges):
    """
    True si la version asset est dans le range vulnérable.
    Si version asset inconnue ou range absent → True (prudence).
    """
    if not asset_version or asset_version == "*":
        return True
    if not cve_version_ranges:
        return True

    for v_range in cve_version_ranges:
        # Version exacte
        if v_range.get("version_exact") and v_range["version_exact"] != "*":
            if compare_versions(asset_version, v_range["version_exact"]) == 0:
                return True
            continue

        in_range = True
        if v_range.get("version_start_including"):
            if compare_versions(asset_version, v_range["version_start_including"]) < 0:
                in_range = False
        if v_range.get("version_start_excluding"):
            if compare_versions(asset_version, v_range["version_start_excluding"]) <= 0:
                in_range = False
        if v_range.get("version_end_including"):
            if compare_versions(asset_version, v_range["version_end_including"]) > 0:
                in_range = False
        if v_range.get("version_end_excluding"):
            if compare_versions(asset_version, v_range["version_end_excluding"]) >= 0:
                in_range = False
        if in_range:
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════
# PARSING CPE
# ═══════════════════════════════════════════════════════════════════════

def parse_cpe(cpe_string):
    """
    Parse 'cpe:2.3:o:microsoft:windows_11:21h2:*:*:*'
    -> {'part': 'o', 'vendor': 'microsoft', 'product': 'windows_11', 'version': '21h2'}
    """
    if not cpe_string or not cpe_string.startswith("cpe:"):
        return None
    parts = cpe_string.split(":")
    if len(parts) < 6:
        return None
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5] if parts[5] != "*" else None,
    }


# ═══════════════════════════════════════════════════════════════════════
# PHASE 2 — PRÉ-CLASSIFICATION DÉTERMINISTE
# ═══════════════════════════════════════════════════════════════════════

# CWE particulièrement pertinents en air-gap (privilèges, exécution locale, etc.)
CWE_AIR_GAP_BOOST = {
    "CWE-269",  # Improper Privilege Management
    "CWE-78",   # OS Command Injection
    "CWE-269",  # Privilege Escalation
    "CWE-264",  # Permissions, Privileges
    "CWE-732",  # Incorrect Permission Assignment
    "CWE-426",  # Untrusted Search Path
    "CWE-427",  # Uncontrolled Search Path Element
    "CWE-77",   # Command Injection
    "CWE-787",  # Out-of-bounds Write
    "CWE-119",  # Buffer Overflow
}

OS_FIRMWARE_KEYWORDS = ['os', 'firmware', 'bios', 'uefi', 'kernel', 'system',
                        'operating', 'bootloader', 'hypervisor']
COMPONENT_KEYWORDS = ['library', 'lib', 'plugin', 'module', 'driver']


def calc_pre_triage_score(cve, asset, version_match, cwe_list, priorite_type=2):
    """
    Calcule (score_pre_triage, priorite_pre_triage) selon règles déterministes.

    cve              : dict avec cvss_v3_score, cvss_v3_vector, produit
    asset            : dict avec niveau_criticite
    version_match    : 'affirme' / 'informatif' / 'unknown'
    cwe_list         : liste des CWE_ID associés à la CVE

    Returns: (float 0-10, str priorite)
    """
    base = float(cve.get("cvss_v3_score") or 0.0)
    score = base

    vector = cve.get("cvss_v3_vector") or ""
    # Air-gap : vecteur réseau pénalisé
    if "AV:N" in vector:
        score -= 3.0
    # Air-gap : vecteur local ou physique légèrement bonifié
    if "AV:L" in vector or "AV:P" in vector:
        score += 0.5

    # Version asset confirmée vulnérable → bonus
    if version_match == "affirme":
        score += 1.0
    elif version_match == "informatif":
        # Version inconnue ou range absent : neutre
        pass

    # Type de produit
    produit = (cve.get("produit") or "").lower()
    if any(k in produit for k in OS_FIRMWARE_KEYWORDS):
        score += 0.5
    if any(k in produit for k in COMPONENT_KEYWORDS):
        score -= 1.0

    # Criticité opérationnelle de l'asset
    crit = asset.get("niveau_criticite") or ""
    if crit in ("critique", "eleve"):
        score += 1.0

    # CWE pertinent en air-gap → bonus
    if cwe_list and any(cwe in CWE_AIR_GAP_BOOST for cwe in cwe_list):
        score += 0.5

    # Ajustement selon le type de vulnérabilité (depuis vuln_types.yml)
    if priorite_type == 4:      # RCE, MemCorrupt, CmdInjection, FirmwareBIOS
        score += 1.5
    elif priorite_type == 3:    # LPE, DoS, AuthBypass, FileWrite
        score += 0.5
    elif priorite_type == 1:    # InfoDisc, WeakCrypto, Misconfiguration
        score -= 1.0
    elif priorite_type == 0:    # XSS, CSRF, SSRF, OpenRedirect
        score -= 5.0

    # Clamp 0-10
    score = max(0.0, min(10.0, score))

    # Priorité
    if score >= 9.0:
        priorite = "critique"
    elif score >= 7.0:
        priorite = "haute"
    elif score >= 4.0:
        priorite = "moyenne"
    else:
        priorite = "basse"

    return round(score, 1), priorite


# ═══════════════════════════════════════════════════════════════════════
# PHASE 1 — DÉTECTION BRUTE (4 PASSES)
# ═══════════════════════════════════════════════════════════════════════

def get_cwes_for_cve(cur, cve_id):
    """Récupère la liste des CWE associés à une CVE."""
    cur.execute("SELECT cwe_id FROM cve_cwe WHERE cve_id = %s", (cve_id,))
    return [row["cwe_id"] for row in cur.fetchall()]


def insert_correlation(cur, asset_id, cve_id, type_corr, passe,
                       score_pre, priorite_pre,
                       type_attaque="Unknown", passer_mistral=True):
    """
    Insertion idempotente. Si la corrélation existe déjà, on garde la meilleure
    passe (cpe_full > vendor_product > os_textuel) et on met à jour
    le score pre-triage si la nouvelle passe est meilleure.
    """
    PASSE_PRIORITY = {
        "cpe_full": 0,
        "vendor_product": 1,
        "os_textuel": 2,
    }

    cur.execute("""
        SELECT id, passe_correlation, score_pre_triage
        FROM correlations
        WHERE asset_id = %s AND cve_id = %s
    """, (asset_id, cve_id))
    existing = cur.fetchone()

    if existing:
        # Comparer les passes
        old_passe = existing["passe_correlation"] or "os_textuel"
        if PASSE_PRIORITY.get(passe, 99) < PASSE_PRIORITY.get(old_passe, 99):
            # Nouvelle passe plus précise → on met à jour
            cur.execute("""
                UPDATE correlations
                SET type_correlation = %s,
                    passe_correlation = %s,
                    score_pre_triage = %s,
                    priorite_pre_triage = %s
                WHERE id = %s
            """, (type_corr, passe, score_pre, priorite_pre, existing["id"]))
            return "updated"
        return "skipped"

    # Nouvelle corrélation
    cur.execute("""
        INSERT INTO correlations (
            asset_id, cve_id, type_correlation, passe_correlation,
            score_pre_triage, priorite_pre_triage,
            type_attaque, passer_mistral,
            statut, date_detection
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'nouveau', NOW())
    """, (asset_id, cve_id, type_corr, passe, score_pre, priorite_pre,
          type_attaque, 1 if passer_mistral else 0))
    return "inserted"


def log_reject(cur, asset_id, cve_id, raison, details, asset_version, cve_versions):
    """Log un rejet pour debug des faux négatifs."""
    cur.execute("""
        INSERT INTO correlation_rejects
            (asset_id, cve_id, raison, details, asset_version, cve_versions)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        asset_id, cve_id, raison,
        details, asset_version,
        json.dumps(cve_versions, ensure_ascii=False)[
            :1000] if cve_versions else None
    ))


def ensure_indexes(conn):
    """Crée les index de performance s'ils n'existent pas."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT COUNT(*) as cnt FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'cve'
              AND index_name = 'idx_corr_filter'
        """)
        if cur.fetchone()["cnt"] == 0:
            print("[INDEX] Création index idx_corr_filter sur cve...")
            cur.execute("""
                ALTER TABLE cve
                ADD INDEX idx_corr_filter (fabricant, cvss_v3_score, date_publication)
            """)
            conn.commit()
            print("[INDEX] ✅ Index créé")


def build_cve_cache(cur, vendors: list) -> dict:
    """
    Charge en mémoire toutes les CVE pertinentes pour les vendors donnés.
    Applique les filtres de base (CVSS, date, vecteur réseau) en SQL.
    Retourne un dict {nvd_vendor: [liste de dicts CVE]}.
    """
    cvss_min = cfg_corr("cvss_min", 4.0)
    cvss_network_min = cfg_corr("cvss_network_min", 7.0)
    date_min = cfg_corr("date_min", "2015-01-01")
    vendor_cve_limit = cfg_corr("vendor_cve_limit", 2000)

    cache = {}
    for vendor in vendors:
        limit_clause = f"LIMIT {int(vendor_cve_limit)}" if vendor_cve_limit > 0 else ""
        cur.execute(f"""
            SELECT cve_id, cpe_affected, versions_affectees,
                   cvss_v3_score, cvss_v3_vector, cvss_v3_severity,
                   produit, fabricant, date_publication
            FROM cve
            WHERE fabricant = %s
              AND cvss_v3_score >= %s
              AND date_publication >= %s
              AND NOT (cvss_v3_vector LIKE '%%AV:N%%' AND cvss_v3_score < %s)
            ORDER BY cvss_v3_score DESC
            {limit_clause}
        """, (vendor, cvss_min, date_min, cvss_network_min))
        cves = cur.fetchall()
        cache[vendor] = cves
        suffix = (f" (limité à {vendor_cve_limit})"
                  if vendor_cve_limit > 0 and len(cves) == vendor_cve_limit else "")
        print(f"  [CACHE] {vendor:30s} → {len(cves):>5} CVE chargées{suffix}")

    return cache


def get_asset_version_tokens(asset: dict) -> list[str]:
    """
    Retourne les tokens version pour le matching.
    Utilise les FK normalisées en priorité, fallback sur texte libre.
    """
    type_eq = (asset.get("type_equipement") or "").lower()
    os_based_types = cfg_corr(
        "os_based_types", ["pc", "laptop", "serveur", "raspberry_pi"])
    tokens = set()

    if type_eq in os_based_types:
        if asset.get("os_nvd_product"):
            tokens.add(asset["os_nvd_product"])
        if asset.get("os_version_label"):
            tokens.update(re.findall(
                r'[a-zA-Z0-9]{3,}', asset["os_version_label"]))
        for field in [asset.get("systeme_exploitation"), asset.get("version_os")]:
            if field:
                tokens.update(re.findall(r'\b\d{4,}\b', field))
                tokens.update(re.findall(r'\b\d+[Hh]\d+\b', field))
    else:
        if asset.get("fw_nvd_product"):
            tokens.add(asset["fw_nvd_product"])
        if asset.get("fw_version_label"):
            tokens.update(re.findall(
                r'[a-zA-Z0-9]{3,}', asset["fw_version_label"]))
        if asset.get("bios_nvd_product"):
            tokens.add(asset["bios_nvd_product"])
        for field in [asset.get("version_firmware"), asset.get("version_bios"),
                      asset.get("systeme_exploitation")]:
            if field:
                tokens.update(re.findall(r'\b\d+\.\d+[\.\d]*\b', field))

    return list(filter(None, tokens))


def detect_os_vendor(asset: dict) -> str | None:
    """
    Détecte le vendor NVD depuis les champs OS de l'asset.
    Parcourt systeme_exploitation puis version_os.
    Retourne le nvd_vendor correspondant ou None si non détecté.
    """
    os_vendor_map = cfg_corr("os_vendor_map", {})
    sources = [
        asset.get("systeme_exploitation") or "",
        asset.get("version_os") or "",
    ]
    for source in sources:
        source_lower = source.lower()
        for keyword, vendor in os_vendor_map.items():
            if keyword in source_lower:
                return vendor
    return None


def get_correlation_vendor(asset: dict) -> tuple[str | None, str]:
    """
    Retourne (vendor_cve, raison) selon le type d'équipement.

    Priorité :
      1. os_version_id renseigné → utilise os_nvd_vendor (match exact garanti)
      2. Type OS-based sans os_version_id → détecte depuis systeme_exploitation (fallback)
      3. Type vendor-based → utilise le vendor matériel
    """
    type_eq = (asset.get("type_equipement") or "").lower()
    os_based_types = cfg_corr(
        "os_based_types", ["pc", "laptop", "serveur", "raspberry_pi"])

    if type_eq in os_based_types:
        if asset.get("os_nvd_vendor"):
            return asset["os_nvd_vendor"], f"FK os_version → {asset['os_nvd_vendor']}"
        vendor = detect_os_vendor(asset)
        if vendor:
            return vendor, f"OS textuel détecté → {vendor} (pas de FK — assigne un OS normalisé)"
        return None, f"Type {type_eq} sans OS normalisé ni OS textuel reconnu — asset ignoré"
    else:
        if asset.get("fw_nvd_vendor"):
            return asset["fw_nvd_vendor"], f"FK fw_version → {asset['fw_nvd_vendor']}"
        vendor = asset.get("nvd_vendor")
        if vendor:
            return vendor, f"Vendor matériel → {vendor}"
        return None, "Pas de vendor matériel — asset ignoré"


def get_cve_version_tokens(cve: dict) -> list:
    """Extrait tous les tokens de version depuis une CVE (versions_affectees, produit, description)."""
    tokens = []

    try:
        versions_data = json.loads(cve.get("versions_affectees") or "[]")
    except Exception:
        versions_data = []

    for v_range in versions_data:
        for key in ("version_exact", "version_start_including",
                    "version_start_excluding", "version_end_including",
                    "version_end_excluding"):
            val = v_range.get(key)
            if val and val != "*":
                tokens.append(str(val))
                tokens.extend(re.findall(r'[a-zA-Z0-9]{3,}', str(val)))
                tokens.extend(re.findall(r'\d+(?:\.\d+)+', str(val)))

    produit = cve.get("produit") or ""
    if produit:
        tokens.append(produit)
        tokens.extend(re.findall(r'[a-zA-Z0-9]{3,}', produit))

    description = cve.get("description") or ""
    if description:
        tokens.extend(re.findall(r'\d+(?:\.\d+)+', description))

    return list(set(filter(None, tokens)))


def classify_cve_type(cve_id: str, description: str, cwes: list[str]) -> tuple[str, bool, int]:
    """
    Classifie une CVE depuis vuln_types.yml.
    Retourne (type_attaque, passer_mistral, priorite_type).
    Priorité : CWE > keywords description > Unknown.
    """
    for cwe in cwes:
        if cwe in CWE_TO_TYPE:
            type_id = CWE_TO_TYPE[cwe]
            type_def = VULN_TYPES[type_id]
            return (
                type_id,
                type_def.get("passer_mistral", True),
                type_def.get("priorite", 2),
            )

    desc_lower = (description or "").lower()
    for keyword, type_id in KEYWORDS_TO_TYPE:
        if keyword in desc_lower:
            type_def = VULN_TYPES[type_id]
            return (
                type_id,
                type_def.get("passer_mistral", True),
                type_def.get("priorite", 2),
            )

    return ("Unknown", True, 2)


def correlate_pass_vendor_match(cur, asset, stats, cve_cache, verbose=False):
    """
    Passe unique de corrélation :
    - Vendor CVE déterminé par get_correlation_vendor() (OS ou matériel)
    - Pré-filtre les CVE par produit exact si FK normalisée disponible
    - Fallback : matching flou sur product_matches_asset
    """
    vendor_cve, raison = get_correlation_vendor(asset)

    if not vendor_cve:
        if verbose:
            print(f"    [vendor_match] SKIP — {raison}")
        return

    if verbose:
        print(f"    [vendor_match] {raison}")

    all_cves = cve_cache.get(vendor_cve, [])

    if not all_cves:
        if verbose:
            print(
                f"    [vendor_match] SKIP — 0 CVE en cache pour {vendor_cve}")
        return

    # ── Filtre produit (pré-filtrage avant la boucle) ─────────────────
    type_eq = (asset.get("type_equipement") or "").lower()
    os_based_types = cfg_corr(
        "os_based_types", ["pc", "laptop", "serveur", "raspberry_pi"])

    if type_eq in os_based_types and asset.get("os_nvd_product"):
        target_product = asset["os_nvd_product"]
        cves = [c for c in all_cves if c.get("produit") == target_product]
        if verbose:
            print(f"    [vendor_match] Filtre exact produit={target_product} "
                  f"→ {len(cves)}/{len(all_cves)} CVE retenues")
    elif type_eq not in os_based_types and asset.get("fw_nvd_product"):
        target_product = asset["fw_nvd_product"]
        cves = [c for c in all_cves if c.get("produit") == target_product]
        if verbose:
            print(f"    [vendor_match] Filtre exact firmware={target_product} "
                  f"→ {len(cves)}/{len(all_cves)} CVE retenues")
    else:
        cves = [c for c in all_cves if product_matches_asset(
            c.get("produit"), asset)]
        if verbose:
            print(f"    [vendor_match] Fallback matching flou "
                  f"→ {len(cves)}/{len(all_cves)} CVE retenues")

    version_match_required = cfg_corr("version_match_required", True)
    version_min_chars = cfg_corr("version_match_min_chars", 4)
    product_bonus = cfg_corr("product_match_bonus", True)
    product_min_chars = cfg_corr("product_match_min_chars", 6)

    # Produits NVD exacts depuis les FK os_versions (match direct, priorité maximale)
    exact_products = set(filter(None, [
        asset.get("os_nvd_product"),
        asset.get("fw_nvd_product"),
        asset.get("bios_nvd_product"),
    ]))
    has_fk = bool(exact_products)

    asset_tokens = get_asset_version_tokens(asset)
    has_version_info = bool(asset_tokens)

    candidates = retenues = rejetees_version = fk_matches = 0

    for cve in cves:
        if cve.get("fabricant") != vendor_cve:
            continue

        candidates += 1
        cve_produit = cve.get("produit") or ""

        # ── Match exact FK (os_version_id / fw_version_id / bios_version_id) ──
        if has_fk and cve_produit in exact_products:
            cwes = get_cwes_for_cve(cur, cve["cve_id"])
            type_attaque, passer_mistral, priorite_type = classify_cve_type(
                cve["cve_id"], cve.get("description", ""), cwes
            )
            score, priorite = calc_pre_triage_score(
                cve, asset, "affirme", cwes, priorite_type)
            result = insert_correlation(cur, asset["asset_id"], cve["cve_id"],
                                        "affirme", "vendor_product", score, priorite,
                                        type_attaque=type_attaque, passer_mistral=passer_mistral)
            stats[result] = stats.get(result, 0) + 1
            retenues += 1
            fk_matches += 1
            continue

        # ── Match version fuzzy (fallback) ────────────────────────────
        cve_tokens = get_cve_version_tokens(cve)

        version_matched = False
        best_version_score = 0

        if not has_version_info or not cve_tokens:
            version_matched = True
        else:
            for a_tok in asset_tokens:
                for c_tok in cve_tokens:
                    s = common_chars_count(a_tok, c_tok)
                    if s > best_version_score:
                        best_version_score = s
                    if s >= version_min_chars:
                        version_matched = True
                        break
                if version_matched:
                    break

        if version_match_required and not version_matched:
            rejetees_version += 1
            log_reject(
                cur, asset["asset_id"], cve["cve_id"],
                "version_hors_range",
                f"Meilleur score version={best_version_score} < {version_min_chars} requis",
                str(asset.get("version_os") or asset.get("version_firmware") or
                    asset.get("systeme_exploitation") or ""),
                []
            )
            continue

        # ── Match produit (bonus) ──────────────────────────────────────
        product_score = 0
        if product_bonus:
            for field in [asset.get("nvd_product"), asset.get("systeme_exploitation"),
                          asset.get("version_os")]:
                if field:
                    s = common_chars_count(cve_produit, field)
                    if s > product_score:
                        product_score = s

        # ── Type de corrélation ────────────────────────────────────────
        if version_matched and has_version_info and best_version_score >= version_min_chars:
            type_corr = "affirme"
            version_match_type = "affirme"
        else:
            type_corr = "informatif"
            version_match_type = "informatif"

        cwes = get_cwes_for_cve(cur, cve["cve_id"])
        type_attaque, passer_mistral, priorite_type = classify_cve_type(
            cve["cve_id"], cve.get("description", ""), cwes
        )
        score, priorite = calc_pre_triage_score(
            cve, asset, version_match_type, cwes, priorite_type)

        # Bonus produit
        if product_bonus and product_score >= product_min_chars:
            score = min(10.0, score + 0.5)
            if score >= 9.0:
                priorite = "critique"
            elif score >= 7.0:
                priorite = "haute"
            elif score >= 4.0:
                priorite = "moyenne"
            else:
                priorite = "basse"

        result = insert_correlation(cur, asset["asset_id"], cve["cve_id"],
                                    type_corr, "vendor_product", score, priorite,
                                    type_attaque=type_attaque, passer_mistral=passer_mistral)
        stats[result] = stats.get(result, 0) + 1
        retenues += 1

    if verbose:
        fk_info = f" ({fk_matches} exact FK)" if fk_matches else ""
        print(f"    [vendor_match] {candidates} candidates → {retenues} retenues"
              f"{fk_info} ({rejetees_version} rejet version)")


# ═══════════════════════════════════════════════════════════════════════
# COMMANDE : correlate
# ═══════════════════════════════════════════════════════════════════════

@app.command()
def correlate(
    dry_run: bool = typer.Option(cfg_corr("dry_run", False), "--dry-run",
                                 help="Affiche sans insérer"),
    verbose: bool = typer.Option(
        cfg_corr("verbose", False), "--verbose/--no-verbose", "-v"),
):
    """Phase 1+2 : détection brute (passes) + pré-classification déterministe."""
    print("\n" + "=" * 70)
    print("  CORRÉLATION CVE / ASSETS — Architecture multi-passes")
    print("=" * 70 + "\n")

    conn = get_connection()
    cur = dict_cursor(conn)

    ensure_indexes(conn)

    cur.execute("""
        SELECT
            a.id                  AS asset_id,
            a.nom_interne,
            a.type_equipement,
            a.niveau_criticite,
            a.statut_operationnel,
            pv.nvd_vendor,
            pm.nvd_product,
            a.os_version_id,
            osv.nvd_vendor        AS os_nvd_vendor,
            osv.nvd_product       AS os_nvd_product,
            osv.os_nom            AS os_nom,
            osv.version           AS os_version_label,
            a.fw_version_id,
            fwv.nvd_vendor        AS fw_nvd_vendor,
            fwv.nvd_product       AS fw_nvd_product,
            fwv.os_nom            AS fw_nom,
            fwv.version           AS fw_version_label,
            a.bios_version_id,
            biosv.nvd_vendor      AS bios_nvd_vendor,
            biosv.nvd_product     AS bios_nvd_product,
            a.systeme_exploitation,
            a.version_os,
            a.version_firmware,
            a.version_bios
        FROM assets a
        JOIN product_vendors pv     ON pv.id   = a.vendor_id
        LEFT JOIN product_models pm ON pm.id   = a.model_id
        LEFT JOIN os_versions osv   ON osv.id  = a.os_version_id
        LEFT JOIN os_versions fwv   ON fwv.id  = a.fw_version_id
        LEFT JOIN os_versions biosv ON biosv.id = a.bios_version_id
        JOIN sites s                ON s.id    = a.site_id
        JOIN clients c              ON c.id    = s.client_id
        WHERE a.statut_operationnel NOT IN ('hors_service', 'inactif')
          AND a.vendor_id IS NOT NULL
    """)
    assets = cur.fetchall()

    if not assets:
        print("⚠️  Aucun asset actif trouvé.\n")
        conn.close()
        raise typer.Exit()

    print(f"Assets à analyser : {len(assets)}")

    print("\n[ASSETS] État normalisation OS :")
    for asset in assets:
        os_info = asset.get("os_nvd_product") or "⚠️  non normalisé"
        fw_info = asset.get("fw_nvd_product") or "—"
        print(
            f"  {asset['nom_interne']:20s} | OS: {os_info:30s} | FW: {fw_info}")
    print()

    print("\n[STRATÉGIE PAR ASSET]")
    vendors_uniques = set()
    for asset in assets:
        vendor_cve, raison = get_correlation_vendor(asset)
        nom = asset["nom_interne"] or ""
        type_eq = asset["type_equipement"] or ""
        print(f"  {nom:25s} ({type_eq:15s}) → {raison}")
        if vendor_cve:
            vendors_uniques.add(vendor_cve)
    vendors_uniques = list(vendors_uniques)
    print(
        f"\nVendors CVE distincts : {len(vendors_uniques)} → {', '.join(vendors_uniques)}\n")

    print("[VÉRIFICATION] CVE disponibles par vendor :")
    for vendor in vendors_uniques:
        cur.execute(
            "SELECT COUNT(*) as nb FROM cve WHERE fabricant = %s", (vendor,))
        nb = cur.fetchone()["nb"]
        flag = "⚠️  AUCUNE CVE" if nb == 0 else f"{nb:>6} CVE totales"
        print(f"  {vendor:30s} → {flag}")
    print()

    print("[CACHE] Chargement des CVE par vendor...")
    t_cache_start = time.time()
    cve_cache = build_cve_cache(cur, vendors_uniques)
    print(f"[CACHE] ✅ Chargé en {time.time() - t_cache_start:.1f}s\n")

    print(f"Passe : vendor_match (vendor obligatoire + version scoring)\n")
    if dry_run:
        print("⚠️  Mode DRY-RUN : aucune insertion en base\n")

    global_stats = {"inserted": 0, "updated": 0, "skipped": 0}
    t_total_start = time.time()

    for i, asset in enumerate(assets, 1):
        asset_name = asset["nom_interne"]
        vendor_cve, _ = get_correlation_vendor(asset)
        nb_cves_cache = len(cve_cache.get(vendor_cve, [])) if vendor_cve else 0

        label_vendor = vendor_cve or "?"
        print(f"\n[Asset {i}/{len(assets)}] {asset_name} ({label_vendor})"
              f" — {nb_cves_cache} CVE en cache")

        if nb_cves_cache == 0:
            print(
                f"  ⚠️  Aucune CVE en cache pour {label_vendor} — asset ignoré")
            continue

        local_stats = {"inserted": 0, "updated": 0, "skipped": 0}
        t_asset_start = time.time()

        correlate_pass_vendor_match(
            cur, asset, local_stats, cve_cache, verbose)

        if not dry_run:
            conn.commit()
        else:
            conn.rollback()

        t_asset = time.time() - t_asset_start
        print(f"  ✅ +{local_stats['inserted']} nouvelles | "
              f"~{local_stats['updated']} mises à jour | "
              f"={local_stats['skipped']} skippées | "
              f"⏱ {t_asset:.1f}s")

        for k in global_stats:
            global_stats[k] += local_stats.get(k, 0)

    t_total = time.time() - t_total_start
    conn.close()

    print(f"\n{'='*70}")
    print(f"  ✅ Nouvelles corrélations         : {global_stats['inserted']}")
    print(f"  🔄 Mises à jour (passe meilleure) : {global_stats['updated']}")
    print(f"  ⏭️  Skippées (déjà présentes)      : {global_stats['skipped']}")
    print(f"  ⏱  Durée totale                   : {t_total:.1f}s")
    print(f"{'='*70}\n")


# ═══════════════════════════════════════════════════════════════════════
# PHASE 3 — ANALYSE MISTRAL
# ═══════════════════════════════════════════════════════════════════════

MISTRAL_SYSTEM_PROMPT = """
Tu es un expert PATCH MANAGEMENT pour environnements air-gapped (isolés d'Internet).

Une corrélation CVE↔asset t'est soumise. Elle a déjà un score de pré-triage
calculé par des règles déterministes. Ta mission est de TRIER, pas de scorer.

Verdicts possibles :
- "patcher"      : asset vulnérable, patch nécessaire
- "informatif"   : pertinent mais pas urgent (à surveiller)
- "faux_positif" : ne concerne pas vraiment cet asset

Tu réponds UNIQUEMENT en JSON valide, sans markdown, sans préambule.
"""

MISTRAL_USER_PROMPT = """
ÉQUIPEMENT :
- Nom : {nom_interne}
- Type : {type_equipement}
- Fabricant : {nvd_vendor}
- Modèle : {model_nom}
- OS : {systeme_exploitation}
- Versions : OS={version_os} | FW={version_firmware} | BIOS={version_bios}
- Criticité : {niveau_criticite}

CVE :
- ID : {cve_id}
- Description : {description}
- CVSS v3 : {cvss_v3_score} ({cvss_v3_severity}) — {cvss_v3_vector}
- Produit : {produit}
- Versions vulnérables : {versions_affectees}

PRÉ-TRIAGE LOCAL :
- Score calculé : {score_pre_triage}/10
- Priorité calculée : {priorite_pre_triage}
- Méthode de match : {passe_correlation}
- Type : {type_correlation}

Réponds en JSON :
{{
  "verdict": "patcher" | "informatif" | "faux_positif",
  "ajustement_score": -2.0 à +2.0,
  "exploitable_air_gap": true | false | null,
  "justification": "1-2 phrases max",
  "recommandation": "Action concrète (ex: patcher vers FortiOS 7.2.5)"
}}

RÈGLES :
- Si la CVE concerne clairement l'OS/firmware → "patcher"
- Si la CVE concerne un composant non vérifiable sur cet asset → "informatif"
- Si la CVE ne s'applique pas du tout (mauvais produit, version OK) → "faux_positif"
- ajustement_score : -2 si air-gap rend ça moins exploitable, +2 si plus dangereux
"""


def analyze_with_mistral(client, correlation, max_retries=None):
    """Envoie une corrélation à Mistral avec retry sur rate limit. Retourne dict ou None."""
    if max_retries is None:
        max_retries = cfg_mistral("max_retries", 3)

    prompt = MISTRAL_USER_PROMPT.format(
        nom_interne=correlation["nom_interne"] or "N/A",
        type_equipement=correlation["type_equipement"] or "N/A",
        nvd_vendor=correlation["nvd_vendor"] or "N/A",
        model_nom=correlation["model_nom"] or "N/A",
        systeme_exploitation=correlation["systeme_exploitation"] or "N/A",
        version_os=correlation["version_os"] or "N/A",
        version_firmware=correlation["version_firmware"] or "N/A",
        version_bios=correlation["version_bios"] or "N/A",
        niveau_criticite=correlation["niveau_criticite"] or "N/A",
        cve_id=correlation["cve_id"],
        description=(correlation["description"] or "")[:600],
        cvss_v3_score=correlation["cvss_v3_score"] or "N/A",
        cvss_v3_severity=correlation["cvss_v3_severity"] or "N/A",
        cvss_v3_vector=correlation["cvss_v3_vector"] or "N/A",
        produit=correlation["produit"] or "N/A",
        versions_affectees=json.dumps(
            correlation["versions_affectees"] or [], ensure_ascii=False
        )[:400],
        score_pre_triage=correlation["score_pre_triage"] or "N/A",
        priorite_pre_triage=correlation["priorite_pre_triage"] or "N/A",
        passe_correlation=correlation["passe_correlation"] or "N/A",
        type_correlation=correlation["type_correlation"] or "N/A",
    )

    for attempt in range(max_retries):
        try:
            response = client.chat.complete(
                model=MISTRAL_MODEL,
                messages=[
                    {"role": "system", "content": MISTRAL_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=cfg_mistral("max_tokens", 512),
            )
            raw = response.choices[0].message.content.strip()

            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            return json.loads(raw)

        except json.JSONDecodeError as e:
            log.error(f"JSON invalide pour {correlation['cve_id']} : {e}")
            return None

        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "rate_limit" in error_str.lower():
                wait = (attempt + 1) * 20  # 20s, 40s, 60s
                log.warning(
                    f"Rate limit sur {correlation['cve_id']} "
                    f"(tentative {attempt + 1}/{max_retries}) "
                    f"— attente {wait}s"
                )
                time.sleep(wait)
                continue
            log.error(
                f"Erreur Mistral pour {correlation['cve_id']} : {type(e).__name__}: {e}"
            )
            return None

    log.error(
        f"Échec après {max_retries} tentatives pour {correlation['cve_id']}")
    return None


# Mapping verdict Mistral → statut BDD
VERDICT_TO_STATUT = {
    "patcher": "confirme",
    "informatif": "informatif",
    "faux_positif": "faux_positif",
}


@app.command()
def analyze(
    batch_max: int = typer.Option(cfg_mistral("batch_max", 0), "--batch-max"),
    asset_id: Optional[int] = typer.Option(None, "--asset-id"),
    force: bool = typer.Option(cfg_mistral("force", False), "--force"),
):
    """
    Phase 3 : Mistral confirme/infirme et ajuste les corrélations.
    Traite par score_pre_triage DESC pour prioriser les plus importantes.
    """
    print("\n" + "=" * 70)
    print("  ANALYSE MISTRAL — Validation contextuelle")
    print("=" * 70 + "\n")

    if not MISTRAL_API_KEY:
        print("❌ MISTRAL_API_KEY non définie\n")
        raise typer.Exit(1)

    mistral_client = Mistral(api_key=MISTRAL_API_KEY)
    conn = get_connection()
    cur = dict_cursor(conn)

    if not force:
        statut_filter = "co.statut = 'nouveau' AND co.date_analyse IS NULL"
        print("Mode : nouvelles corrélations uniquement")
    else:
        statut_filter = "co.statut IN ('nouveau','en_analyse','confirme','informatif','faux_positif')"
        print("⚠️  Mode FORCE : réanalyse tout")

    asset_clause = f"AND co.asset_id = {asset_id}" if asset_id else ""
    limit_clause = f"LIMIT {batch_max}" if batch_max > 0 else ""

    cur.execute(f"""
        SELECT
            co.id                 AS correlation_id,
            co.asset_id, co.cve_id,
            co.type_correlation, co.passe_correlation,
            co.score_pre_triage, co.priorite_pre_triage,
            co.type_attaque,
            a.nom_interne, a.type_equipement,
            a.systeme_exploitation,
            a.version_os, a.version_firmware, a.version_bios,
            a.niveau_criticite,
            pv.nvd_vendor,
            pm.nom                AS model_nom,
            s.nom                 AS site_nom,
            cv.description, cv.cvss_v3_score, cv.cvss_v3_severity,
            cv.cvss_v3_vector, cv.produit, cv.versions_affectees
        FROM correlations co
        JOIN assets a        ON a.id        = co.asset_id
        JOIN cve cv          ON cv.cve_id   = co.cve_id
        JOIN product_vendors pv ON pv.id    = a.vendor_id
        LEFT JOIN product_models pm ON pm.id = a.model_id
        LEFT JOIN sites s    ON s.id         = a.site_id
        WHERE {statut_filter}
          AND co.passer_mistral = 1
        {asset_clause}
        ORDER BY co.score_pre_triage DESC, cv.cvss_v3_score DESC
        {limit_clause}
    """)
    correlations = cur.fetchall()

    if not correlations:
        print("✅ Aucune nouvelle corrélation à analyser\n")
        conn.close()
        return

    cur.execute(
        "SELECT COUNT(*) as nb FROM correlations WHERE passer_mistral = 0 AND statut = 'nouveau'"
    )
    nb_ignores = cur.fetchone()["nb"]

    if batch_max > 0:
        print(f"Limite batch : {batch_max}")
    print(f"CVE ignorées (non pertinentes air-gap) : {nb_ignores}")
    print(f"CVE à analyser par Mistral             : {len(correlations)}\n")

    counters = {"confirme": 0, "informatif": 0, "faux_positif": 0, "errors": 0}

    total = len(correlations)
    for idx, corr in enumerate(correlations, 1):
        asset_name = corr["nom_interne"]
        site_name = corr.get("site_nom", "?")
        cve_id = corr["cve_id"]
        type_attaque = corr.get("type_attaque", "Unknown")

        print(
            f"[ {idx:>4} / {total} ] — {asset_name} [ {site_name} ] — {cve_id}", flush=True)

        cur.execute(
            "UPDATE correlations SET statut = 'en_analyse' WHERE id = %s",
            (corr["correlation_id"],)
        )
        conn.commit()

        if isinstance(corr["versions_affectees"], str):
            try:
                corr["versions_affectees"] = json.loads(
                    corr["versions_affectees"])
            except Exception:
                corr["versions_affectees"] = []

        result = analyze_with_mistral(mistral_client, corr)

        if result is None:
            counters["errors"] += 1
            cur.execute(
                "UPDATE correlations SET statut = 'nouveau' WHERE id = %s",
                (corr["correlation_id"],)
            )
            conn.commit()
            print(f"         ⚠️  Erreur Mistral — remis en file", flush=True)
        else:
            verdict = result.get("verdict", "informatif")
            statut_final = VERDICT_TO_STATUT.get(verdict, "informatif")
            counters[statut_final] = counters.get(statut_final, 0) + 1

            # Score final = pré-triage + ajustement Mistral
            ajust = float(result.get("ajustement_score", 0) or 0)
            ajust = max(-2.0, min(2.0, ajust))
            score_final = float(corr["score_pre_triage"] or 0) + ajust
            score_final = max(0.0, min(10.0, score_final))

            # Priorité finale recalculée depuis score final
            if score_final >= 9.0:
                priorite_finale = "critique"
            elif score_final >= 7.0:
                priorite_finale = "haute"
            elif score_final >= 4.0:
                priorite_finale = "moyenne"
            else:
                priorite_finale = "basse"

            analyse_text = (
                f"[Verdict Mistral: {verdict}] "
                f"[Ajustement: {ajust:+.1f}]\n\n"
                f"{result.get('justification', '')}\n\n"
                f"Recommandation: {result.get('recommandation', '')}"
            )

            cur.execute("""
                UPDATE correlations SET
                    statut = %s,
                    priorite = %s,
                    score_contextuel = %s,
                    exploitable_air_gap = %s,
                    analyse_mistral = %s,
                    risque_reel = %s,
                    date_analyse = NOW()
                WHERE id = %s
            """, (
                statut_final,
                priorite_finale,
                round(score_final, 1),
                result.get("exploitable_air_gap"),
                analyse_text,
                result.get("recommandation", "")[:1000],
                corr["correlation_id"],
            ))
            conn.commit()

            verdict_icon = {"confirme": "✅", "informatif": "📋",
                            "faux_positif": "❌"}.get(statut_final, "?")
            print(
                f"         {verdict_icon} {statut_final} | score={round(score_final, 1)} | {type_attaque}", flush=True)

        time.sleep(MISTRAL_DELAY)

    conn.close()

    print(f"\n{'='*70}")
    print(f"  ✅ À patcher (confirme)  : {counters['confirme']}")
    print(f"  📋 Informatif            : {counters['informatif']}")
    print(f"  ❌ Faux positifs         : {counters['faux_positif']}")
    print(f"  ⚠️  Erreurs              : {counters['errors']}")
    print(f"{'='*70}\n")


# ═══════════════════════════════════════════════════════════════════════
# RAPPORTS PDF (inchangé — utilise les nouvelles colonnes au passage)
# ═══════════════════════════════════════════════════════════════════════

PRIORITY_COLORS = {
    "critique": colors.HexColor("#C0392B"),
    "haute":    colors.HexColor("#E67E22"),
    "moyenne":  colors.HexColor("#F1C40F"),
    "basse":    colors.HexColor("#27AE60"),
}

PRIORITY_ORDER = {"critique": 0, "haute": 1, "moyenne": 2, "basse": 3, None: 4}


def build_pdf_styles():
    styles = getSampleStyleSheet()
    custom = {
        "title": ParagraphStyle("title", parent=styles["Title"],
                                fontSize=22, spaceAfter=6, textColor=colors.HexColor("#1A252F")),
        "subtitle": ParagraphStyle("subtitle", parent=styles["Normal"],
                                   fontSize=11, textColor=colors.HexColor("#5D6D7E"), spaceAfter=20),
        "h1": ParagraphStyle("h1", parent=styles["Heading1"],
                             fontSize=16, textColor=colors.HexColor("#1A252F"),
                             spaceBefore=20, spaceAfter=8, borderPad=4),
        "h2": ParagraphStyle("h2", parent=styles["Heading2"],
                             fontSize=13, textColor=colors.HexColor("#2C3E50"),
                             spaceBefore=14, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=styles["Heading3"],
                             fontSize=11, textColor=colors.HexColor("#34495E"),
                             spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("body", parent=styles["Normal"],
                               fontSize=9, leading=13, spaceAfter=4),
        "small": ParagraphStyle("small", parent=styles["Normal"],
                                fontSize=8, leading=11, textColor=colors.HexColor("#5D6D7E")),
    }
    return {**{k: styles[k] for k in styles.byName}, **custom}


@app.command()
def report(
    output_dir: str = typer.Option(
        str(BASE_DIR / cfg_rapport("output_dir", "documents")), "--output-dir", "-d"),
    statuts: str = typer.Option(
        ",".join(cfg_rapport("statuts_inclus", [
                 "confirme", "informatif", "mitige"])),
        "--statuts"),
    min_score: float = typer.Option(
        cfg_rapport("score_min", 0.0), "--min-score"),
    client_id: Optional[int] = typer.Option(None, "--client-id"),
    asset_id: Optional[int] = typer.Option(None, "--asset-id"),
):
    """Génère 2 PDFs : synthèse + rapport complet."""
    # Note : génération PDF reprise telle quelle de la version précédente.
    # À adapter avec les nouvelles colonnes (score_pre_triage, passe_correlation)
    # si tu veux les exposer dans le rapport.
    print("⚠️  Commande report : à brancher manuellement sur la nouvelle structure.")
    print("   Utilise la vue v_vulnerabilites_tableau dans Grafana en attendant.\n")


# ═══════════════════════════════════════════════════════════════════════
# RUN-ALL
# ═══════════════════════════════════════════════════════════════════════

@app.command("run-all")
def run_all(
    batch_max: int = typer.Option(cfg_mistral("batch_max", 0), "--batch-max"),
    verbose: bool = typer.Option(
        cfg_corr("verbose", False), "--verbose/--no-verbose", "-v"),
):
    """Pipeline complet : corrélation → analyse Mistral."""
    print("\n" + "=" * 70)
    print("  PIPELINE COMPLET : CORRÉLATION → ANALYSE")
    print("=" * 70)

    correlate(dry_run=False, verbose=verbose)
    analyze(batch_max=batch_max, asset_id=None, force=False)

    print("=" * 70)
    print("  ✅ PIPELINE TERMINÉ")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.append("run-all")
    app()
