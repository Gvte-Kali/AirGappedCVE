#!/usr/bin/env python3
"""
import_vendors_models.py
------------------------
Parcourt tous les fichiers JSON NVD dans data/nvd/raw/,
extrait les couples (vendor, product) depuis les strings CPE,
et les insère directement dans MariaDB (product_vendors + product_models).

Tables cibles :
  product_vendors : nom (affiché), nvd_vendor (NVD lowercase)
  product_models  : vendor_id, nom (affiché), nvd_product, cpe_part, type_produit, cpe_base

Doublons : INSERT IGNORE — skip silencieux garanti par les UNIQUE KEY de la BDD.

Usage :
    python3 scripts/import_vendors_models.py
    python3 scripts/import_vendors_models.py --raw-dir data/nvd/raw --batch-size 500
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import pymysql
from dotenv import load_dotenv

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_PATH = Path("logs/import_vendors_models.log")
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)


# ── CPE parsing ────────────────────────────────────────────────────────────────
CPE_PART_MAP = {"a": "application", "o": "os", "h": "hardware"}


def parse_cpe(cpe_string: str) -> dict | None:
    """
    Extrait les infos utiles depuis une string CPE 2.3.
    Retourne None si invalide ou champs jokers.

    Format : cpe:2.3:<part>:<vendor>:<product>:<version>:...
    """
    parts = cpe_string.split(":")
    if len(parts) < 5:
        return None

    cpe_part = parts[2].strip()   # a / o / h
    nvd_vendor = parts[3].strip()
    nvd_product = parts[4].strip()

    if not nvd_vendor or nvd_vendor in ("*", "-"):
        return None
    if not nvd_product or nvd_product in ("*", "-"):
        return None

    # Nom affiché = underscores → espaces, title case
    nom_vendor = nvd_vendor.replace("_", " ").title()
    nom_product = nvd_product.replace("_", " ").title()

    type_produit = CPE_PART_MAP.get(cpe_part, "application")
    cpe_base = f"cpe:2.3:{cpe_part}:{nvd_vendor}:{nvd_product}"

    return {
        "nvd_vendor":   nvd_vendor,
        "nom_vendor":   nom_vendor,
        "nvd_product":  nvd_product,
        "nom_product":  nom_product,
        "cpe_part":     cpe_part if cpe_part in ("a", "o", "h") else "a",
        "type_produit": type_produit,
        "cpe_base":     cpe_base,
    }


def extract_pairs_from_file(json_path: Path) -> list[dict]:
    """Extrait toutes les entrées CPE uniques (vendor+product) d'un fichier NVD JSON."""
    seen: set[tuple[str, str]] = set()
    results: list[dict] = []

    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.warning(f"Impossible de lire {json_path.name} : {e}")
        return results

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    parsed = parse_cpe(match.get("criteria", ""))
                    if not parsed:
                        continue
                    key = (parsed["nvd_vendor"], parsed["nvd_product"])
                    if key not in seen:
                        seen.add(key)
                        results.append(parsed)

    return results


# ── DB helpers ─────────────────────────────────────────────────────────────────
def get_connection(db_cfg: dict) -> pymysql.Connection:
    return pymysql.connect(
        host=db_cfg["host"],
        port=int(db_cfg["port"]),
        user=db_cfg["user"],
        password=db_cfg["password"],
        database=db_cfg["name"],
        charset="utf8mb4",
        autocommit=False,
    )


def insert_vendors_batch(cursor, vendors: list[dict]) -> int:
    """INSERT IGNORE dans product_vendors. Retourne le nb de lignes insérées."""
    if not vendors:
        return 0
    sql = "INSERT IGNORE INTO product_vendors (nom, nvd_vendor) VALUES (%s, %s)"
    rows = [(v["nom_vendor"], v["nvd_vendor"]) for v in vendors]
    cursor.executemany(sql, rows)
    return cursor.rowcount


def fetch_vendor_ids(cursor, nvd_vendors: list[str]) -> dict[str, int]:
    """Récupère le mapping nvd_vendor → id pour une liste de vendors."""
    if not nvd_vendors:
        return {}
    placeholders = ",".join(["%s"] * len(nvd_vendors))
    cursor.execute(
        f"SELECT id, nvd_vendor FROM product_vendors WHERE nvd_vendor IN ({placeholders})",
        nvd_vendors,
    )
    return {row[1]: row[0] for row in cursor.fetchall()}


def insert_models_batch(cursor, models: list[dict], vendor_ids: dict[str, int]) -> int:
    """INSERT IGNORE dans product_models. Retourne le nb de lignes insérées."""
    if not models:
        return 0
    sql = """
        INSERT IGNORE INTO product_models
            (vendor_id, nom, nvd_product, cpe_part, type_produit, cpe_base)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    rows = []
    for m in models:
        vid = vendor_ids.get(m["nvd_vendor"])
        if not vid:
            continue
        rows.append((
            vid,
            m["nom_product"],
            m["nvd_product"],
            m["cpe_part"],
            m["type_produit"],
            m["cpe_base"],
        ))
    if not rows:
        return 0
    cursor.executemany(sql, rows)
    return cursor.rowcount


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Import vendors/models NVD → MariaDB")
    parser.add_argument("--raw-dir",    default="data/nvd/raw",
                        help="Dossier JSON NVD (défaut: data/nvd/raw)")
    parser.add_argument("--batch-size", type=int, default=500,
                        help="Taille des batches SQL (défaut: 500)")
    parser.add_argument("--env-file",   default=".env",
                        help="Chemin vers le fichier .env (défaut: .env)")
    args = parser.parse_args()

    # ── Config BDD depuis .env ─────────────────────────────────────────────────
    load_dotenv(args.env_file)
    db_cfg = {
        "host":     os.getenv("DB_HOST", "localhost"),
        "port":     os.getenv("DB_PORT", "3306"),
        "user":     os.getenv("DB_USER", "avea"),
        "password": os.getenv("DB_PASSWORD", ""),
        "name":     os.getenv("DB_NAME", "asset_vuln_manager"),
    }

    raw_dir = Path(args.raw_dir)
    if not raw_dir.exists():
        log.error(f"Dossier introuvable : {raw_dir}")
        sys.exit(1)

    json_files = sorted(raw_dir.glob("*.json"))
    if not json_files:
        log.error(f"Aucun fichier JSON dans {raw_dir}")
        sys.exit(1)

    log.info("=== Démarrage import vendors/models NVD → MariaDB ===")
    log.info(f"Source   : {raw_dir}  ({len(json_files)} fichiers)")
    log.info(f"Base     : {db_cfg['name']}@{db_cfg['host']}")
    log.info(f"Batch    : {args.batch_size}")

    # ── Étape 1 : extraction CPE ───────────────────────────────────────────────
    log.info("── Étape 1/3 : extraction des CPE depuis les fichiers JSON…")
    all_entries: list[dict] = []
    seen_global: set[tuple[str, str]] = set()

    for i, jf in enumerate(json_files, 1):
        entries = extract_pairs_from_file(jf)
        new = 0
        for e in entries:
            key = (e["nvd_vendor"], e["nvd_product"])
            if key not in seen_global:
                seen_global.add(key)
                all_entries.append(e)
                new += 1
        log.info(
            f"  [{i:>4}/{len(json_files)}] {jf.name} → +{new} nouveaux (total: {len(all_entries)})")

    unique_vendors = list({e["nvd_vendor"]: e for e in all_entries}.values())
    log.info(
        f"Extraction terminée : {len(all_entries)} couples, {len(unique_vendors)} vendors distincts")

    # ── Étape 2 : INSERT vendors ───────────────────────────────────────────────
    log.info("── Étape 2/3 : insertion vendors dans product_vendors…")
    conn = get_connection(db_cfg)
    vendors_inserted = 0

    try:
        with conn.cursor() as cur:
            for i in range(0, len(unique_vendors), args.batch_size):
                batch = unique_vendors[i:i + args.batch_size]
                n = insert_vendors_batch(cur, batch)
                vendors_inserted += n
                conn.commit()
                pct = int((i + len(batch)) / len(unique_vendors) * 100)
                log.info(
                    f"  vendors {i+1}–{i+len(batch)}/{len(unique_vendors)} ({pct}%) → {n} insérés ce batch")

        log.info(
            f"Vendors : {vendors_inserted} insérés, {len(unique_vendors) - vendors_inserted} déjà existants (ignorés)")

        # ── Étape 3 : INSERT models ────────────────────────────────────────────
        log.info("── Étape 3/3 : insertion modèles dans product_models…")
        models_inserted = 0
        total = len(all_entries)

        with conn.cursor() as cur:
            for i in range(0, total, args.batch_size):
                batch = all_entries[i:i + args.batch_size]

                # Résoudre les vendor_ids pour ce batch
                nvd_vendors_batch = list({e["nvd_vendor"] for e in batch})
                vendor_ids = fetch_vendor_ids(cur, nvd_vendors_batch)

                n = insert_models_batch(cur, batch, vendor_ids)
                models_inserted += n
                conn.commit()
                pct = int((i + len(batch)) / total * 100)
                log.info(
                    f"  modèles {i+1}–{i+len(batch)}/{total} ({pct}%) → {n} insérés ce batch")

        log.info(
            f"Modèles : {models_inserted} insérés, {total - models_inserted} déjà existants (ignorés)")

    except Exception as e:
        conn.rollback()
        log.error(f"Erreur SQL : {e}")
        raise
    finally:
        conn.close()

    log.info("=== Import terminé ===")
    log.info(f"Log complet : {LOG_PATH.resolve()}")


if __name__ == "__main__":
    main()
