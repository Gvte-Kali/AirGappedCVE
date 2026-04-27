#!/usr/bin/env python3
"""
nvd_sync.py — Import des CVE depuis les fichiers JSON du NVD.
Filtre automatiquement selon les vendors/products présents dans le référentiel.
"""

import json
import os
import sys
import glob
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Remonte d'un niveau pour atteindre le répertoire parent
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from database import get_connection



# ──────────────────────────────────────────────
#  Charger les filtres depuis le référentiel
# ──────────────────────────────────────────────
def load_filters(conn):
    """
    Lit product_vendors et product_models.
    Retourne deux structures :
      - vendor_all : set de vendors sans produit spécifique (on prend tout)
      - vendor_products : dict {vendor: set(products)}
    
    Logique :
      - Si un vendor a au moins un model en base → on filtre par product
      - Si un vendor existe mais n'a aucun model → on prend tout le vendor
    """
    with conn.cursor() as cur:
        # Tous les vendors
        cur.execute("SELECT id, nvd_vendor FROM product_vendors")
        vendors = {row["id"]: row["nvd_vendor"] for row in cur.fetchall()}

        # Tous les models groupés par vendor
        cur.execute("""
            SELECT pv.nvd_vendor, pm.nvd_product
            FROM product_models pm
            JOIN product_vendors pv ON pm.vendor_id = pv.id
        """)
        models = cur.fetchall()

    vendor_products = {}
    vendors_with_models = set()

    for row in models:
        v = row["nvd_vendor"]
        p = row["nvd_product"]
        vendor_products.setdefault(v, set()).add(p)
        vendors_with_models.add(v)

    # Vendors sans aucun model → on prend tout
    vendor_all = set()
    for vid, vname in vendors.items():
        if vname not in vendors_with_models:
            vendor_all.add(vname)

    print(f"[FILTRES] Vendors complets (tout prendre) : {vendor_all or 'aucun'}")
    for v, ps in vendor_products.items():
        print(f"[FILTRES] {v} → {ps}")

    return vendor_all, vendor_products


# ──────────────────────────────────────────────
#  Parser un CPE 2.3
# ──────────────────────────────────────────────
def parse_cpe(cpe_string):
    """Retourne (vendor, product, version) depuis un CPE 2.3."""
    parts = cpe_string.split(":")
    if len(parts) >= 6:
        return parts[3].lower(), parts[4].lower(), parts[5] if parts[5] != "*" else None
    return None, None, None


# ──────────────────────────────────────────────
#  Vérifier si une CVE matche nos filtres
# ──────────────────────────────────────────────
def cve_matches_filters(cve_data, vendor_all, vendor_products):
    """
    Parcourt les configurations CPE d'une CVE.
    Retourne la liste des CPE matchés avec leurs infos.
    """
    configurations = cve_data.get("configurations", [])
    matched_cpes = []

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue

                cpe_str = cpe_match.get("criteria", "")
                vendor, product, version = parse_cpe(cpe_str)
                if vendor is None:
                    continue

                match = False

                # Cas 1 : vendor complet
                if vendor in vendor_all:
                    match = True

                # Cas 2 : vendor + product spécifique
                elif vendor in vendor_products and product in vendor_products[vendor]:
                    match = True

                if match:
                    matched_cpes.append({
                        "cpe": cpe_str,
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "version_start_including": cpe_match.get("versionStartIncluding"),
                        "version_start_excluding": cpe_match.get("versionStartExcluding"),
                        "version_end_including": cpe_match.get("versionEndIncluding"),
                        "version_end_excluding": cpe_match.get("versionEndExcluding"),
                    })

    return matched_cpes


# ──────────────────────────────────────────────
#  Extraire les infos d'une CVE
# ──────────────────────────────────────────────
def extract_cve_info(cve_item, matched_cpes):
    """Extrait les champs nécessaires d'un item CVE du NVD."""
    cve_id = cve_item.get("id", "")

    # Description en anglais
    descriptions = cve_item.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # CVSS v3.1 ou v3.0
    metrics = cve_item.get("metrics", {})
    cvss3_score = None
    cvss3_severity = None
    cvss3_vector = None

    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            cvss3_score = cvss_data.get("baseScore")
            cvss3_severity = cvss_data.get("baseSeverity")
            cvss3_vector = cvss_data.get("vectorString")
            break

    # CVSS v2
    cvss2_score = None
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cvss2_data = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss2_score = cvss2_data.get("baseScore")

    # CWE
    cwes = []
    weaknesses = cve_item.get("weaknesses", [])
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    # Premier vendor/product des matchs
    fabricant = matched_cpes[0]["vendor"] if matched_cpes else None
    produit = matched_cpes[0]["product"] if matched_cpes else None

    # Versions affectées structurées
    versions_affectees = []
    for cpe in matched_cpes:
        v_info = {
            "cpe": cpe["cpe"],
            "vendor": cpe["vendor"],
            "product": cpe["product"],
            "version_exact": cpe["version"],
            "version_start_including": cpe["version_start_including"],
            "version_start_excluding": cpe["version_start_excluding"],
            "version_end_including": cpe["version_end_including"],
            "version_end_excluding": cpe["version_end_excluding"],
        }
        versions_affectees.append(v_info)

    # Dates
    date_pub = cve_item.get("published")
    date_mod = cve_item.get("lastModified")

    # URL source
    references = cve_item.get("references", [])
    source_url = references[0].get("url") if references else None

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_v3_score": cvss3_score,
        "cvss_v3_severity": cvss3_severity,
        "cvss_v3_vector": cvss3_vector,
        "cvss_v2_score": cvss2_score,
        "fabricant": fabricant,
        "produit": produit,
        "versions_affectees": json.dumps(versions_affectees),
        "cpe_affected": json.dumps([c["cpe"] for c in matched_cpes]),
        "date_publication": date_pub,
        "date_modification": date_mod,
        "source_url": source_url,
        "cwes": cwes,
    }


# ──────────────────────────────────────────────
#  Insérer ou mettre à jour une CVE
# ──────────────────────────────────────────────
def upsert_cve(conn, cve_info):
    """Insert ou update une CVE dans la base."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO cve (
                cve_id, description, cvss_v3_score, cvss_v3_severity,
                cvss_v3_vector, cvss_v2_score, fabricant, produit,
                versions_affectees, cpe_affected,
                date_publication, date_modification, source_url
            ) VALUES (
                %(cve_id)s, %(description)s, %(cvss_v3_score)s, %(cvss_v3_severity)s,
                %(cvss_v3_vector)s, %(cvss_v2_score)s, %(fabricant)s, %(produit)s,
                %(versions_affectees)s, %(cpe_affected)s,
                %(date_publication)s, %(date_modification)s, %(source_url)s
            )
            ON DUPLICATE KEY UPDATE
                description = VALUES(description),
                cvss_v3_score = VALUES(cvss_v3_score),
                cvss_v3_severity = VALUES(cvss_v3_severity),
                cvss_v3_vector = VALUES(cvss_v3_vector),
                cvss_v2_score = VALUES(cvss_v2_score),
                fabricant = VALUES(fabricant),
                produit = VALUES(produit),
                versions_affectees = VALUES(versions_affectees),
                cpe_affected = VALUES(cpe_affected),
                date_publication = VALUES(date_publication),
                date_modification = VALUES(date_modification),
                source_url = VALUES(source_url)
        """, cve_info)

        # Liaison CWE
        for cwe_id in cve_info.get("cwes", []):
            cur.execute("""
                INSERT IGNORE INTO cve_cwe (cve_id, cwe_id)
                VALUES (%s, %s)
            """, (cve_info["cve_id"], cwe_id))


# ──────────────────────────────────────────────
#  Traiter un fichier JSON du NVD
# ──────────────────────────────────────────────
def process_file(filepath, conn, vendor_all, vendor_products, stats):
    """Traite un fichier JSON NVD."""
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"  [IGNORÉ] Fichier JSON invalide ou vide : {os.path.basename(filepath)} ({e})")
            return

    vulnerabilities = data.get("vulnerabilities", [])
    stats["total_cve"] += len(vulnerabilities)

    for vuln in vulnerabilities:
        cve_item = vuln.get("cve", {})
        matched_cpes = cve_matches_filters(cve_item, vendor_all, vendor_products)

        if not matched_cpes:
            stats["skipped"] += 1
            continue

        cve_info = extract_cve_info(cve_item, matched_cpes)
        upsert_cve(conn, cve_info)
        stats["imported"] += 1

    conn.commit()


# ──────────────────────────────────────────────
#  Point d'entrée
# ──────────────────────────────────────────────
def main():
    # Répertoire des fichiers JSON NVD
    nvd_dir = os.getenv("NVD_DATA_DIR", str(BASE_DIR / "data" / "nvd" / "raw"))

    if not os.path.isdir(nvd_dir):
        print(f"[ERREUR] Répertoire NVD introuvable : {nvd_dir}")
        print("Télécharge les fichiers depuis https://nvd.nist.gov/feeds/json/cve/1.1/")
        sys.exit(1)

    json_files = sorted(glob.glob(os.path.join(nvd_dir, "*.json")))
    if not json_files:
        print(f"[ERREUR] Aucun fichier JSON dans {nvd_dir}")
        sys.exit(1)

    print(f"[NVD SYNC] {len(json_files)} fichiers trouvés dans {nvd_dir}")

    conn = get_connection()
    try:
        vendor_all, vendor_products = load_filters(conn)

        if not vendor_all and not vendor_products:
            print("[ERREUR] Aucun vendor/product en base. Ajoute des entrées dans product_vendors/product_models.")
            sys.exit(1)

        stats = {"total_cve": 0, "imported": 0, "skipped": 0}

        for i, filepath in enumerate(json_files, 1):
            filename = os.path.basename(filepath)
            print(f"[{i}/{len(json_files)}] {filename}...", end=" ", flush=True)
            process_file(filepath, conn, vendor_all, vendor_products, stats)
            print(f"OK")

        print(f"\n[RÉSULTAT]")
        print(f"  CVE parcourues : {stats['total_cve']}")
        print(f"  CVE importées  : {stats['imported']}")
        print(f"  CVE ignorées   : {stats['skipped']}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
