#!/usr/bin/env python3
"""
extract_os_versions.py
──────────────────────
Peuple la table os_versions depuis cve.fabricant + cve.produit.

Applique des règles de normalisation pour générer os_nom et version lisibles.
Peut être relancé autant de fois que nécessaire (INSERT IGNORE).

Usage :
    python3 scripts/extract_os_versions.py
    python3 scripts/extract_os_versions.py --dry-run
    python3 scripts/extract_os_versions.py --verbose
"""

import sys
import os
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from database import get_connection
import argparse
import re
import logging

# Configuration du logging
LOG_DIR = os.path.join(_PROJECT_ROOT, "logs")
LOG_FILE = os.path.join(LOG_DIR, "extract_os_versions.log")
os.makedirs(LOG_DIR, exist_ok=True)

# Fonction de tronquage des logs
def truncate_log_keep_last_lines(log_file, max_size_mb=25, lines_to_keep=10000):
    """Tronque le fichier de log en gardant les dernières `lines_to_keep` lignes si > max_size_mb Mo."""
    max_size = max_size_mb * 1024 * 1024
    if not os.path.exists(log_file) or os.path.getsize(log_file) <= max_size:
        return
    with open(log_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    lines_to_write = lines[-lines_to_keep:] if len(lines) > lines_to_keep else lines
    with open(log_file, 'w', encoding='utf-8') as f:
        f.writelines(lines_to_write)

# Appel pour tronquer le fichier avant de logger
truncate_log_keep_last_lines(LOG_FILE)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


# ═══════════════════════════════════════════════════════════════════════
# RÈGLES DE NORMALISATION
# Format : (pattern_produit, os_nom, version_fn, type_produit)
#   - pattern_produit : regex sur cve.produit
#   - os_nom          : nom affiché (str ou callable(match) -> str)
#   - version_fn      : callable(match) -> str | None
#   - type_produit    : 'os' | 'firmware' | 'bios'
# ═══════════════════════════════════════════════════════════════════════


def _win_ver(match):
    """Extrait la version depuis un produit windows_XX_YYYY."""
    groups = [g for g in match.groups() if g]
    return " ".join(groups).upper() if groups else None


NORMALIZATION_RULES = [

    # ── Microsoft Windows Server ──────────────────────────────────────
    (r'^windows_server_(\d{4})_(\d+h\d+)$',
     "Windows Server", lambda m: f"{m.group(1)} {m.group(2).upper()}", "os"),
    (r'^windows_server_(\d{4})$',
     "Windows Server", lambda m: m.group(1), "os"),
    (r'^windows_server_(\d{4}[a-z0-9_]*)$',
     "Windows Server", lambda m: m.group(1).replace("_", " ").upper(), "os"),
    (r'^windows_server$',
     "Windows Server", lambda m: None, "os"),
    (r'^windows_server_1903$',
     "Windows Server", lambda m: "1903", "os"),

    # ── Microsoft Windows 11 ─────────────────────────────────────────
    (r'^windows_11_(\d+h\d+)$',
     "Windows 11", lambda m: m.group(1).upper(), "os"),
    (r'^windows_11_(\d+)$',
     "Windows 11", lambda m: m.group(1), "os"),
    (r'^windows_11$',
     "Windows 11", lambda m: None, "os"),

    # ── Microsoft Windows 10 ─────────────────────────────────────────
    (r'^windows_10_(\d{4})$',
     "Windows 10", lambda m: m.group(1), "os"),
    (r'^windows_10_(\d+h\d+)$',
     "Windows 10", lambda m: m.group(1).upper(), "os"),
    (r'^windows_10$',
     "Windows 10", lambda m: None, "os"),
    (r'^windows_10_mobile$',
     "Windows 10 Mobile", lambda m: None, "os"),

    # ── Microsoft Windows (autres) ────────────────────────────────────
    (r'^windows_8\.1$',     "Windows 8.1", lambda m: None, "os"),
    (r'^windows_8$',        "Windows 8", lambda m: None, "os"),
    (r'^windows_7$',        "Windows 7", lambda m: None, "os"),
    (r'^windows_vista$',    "Windows Vista", lambda m: None, "os"),
    (r'^windows_xp$',       "Windows XP", lambda m: None, "os"),
    (r'^windows$',          "Windows", lambda m: None, "os"),
    (r'^windows-nt$',       "Windows NT", lambda m: None, "os"),
    (r'^windows_nt$',       "Windows NT", lambda m: None, "os"),

    # ── Synology ─────────────────────────────────────────────────────
    (r'^diskstation_manager$',
     "DSM (DiskStation Manager)", lambda m: None, "os"),
    (r'^dsm$',
     "DSM (DiskStation Manager)", lambda m: None, "os"),
    (r'^router_manager$',
     "Synology Router Manager", lambda m: None, "firmware"),
    (r'^surveillance_station$',
     "Surveillance Station", lambda m: None, "os"),

    # ── Fortinet ─────────────────────────────────────────────────────
    (r'^fortios$',          "FortiOS", lambda m: None, "firmware"),
    (r'^fortigate$',        "FortiGate", lambda m: None, "firmware"),
    (r'^fortimanager$',     "FortiManager", lambda m: None, "firmware"),
    (r'^fortianalyzer$',    "FortiAnalyzer", lambda m: None, "firmware"),

    # ── Cisco ────────────────────────────────────────────────────────
    (r'^ios$',              "Cisco IOS", lambda m: None, "firmware"),
    (r'^ios_xe$',           "Cisco IOS XE", lambda m: None, "firmware"),
    (r'^ios_xr$',           "Cisco IOS XR", lambda m: None, "firmware"),
    (r'^nx-os$',            "Cisco NX-OS", lambda m: None, "firmware"),

    # ── Linux ────────────────────────────────────────────────────────
    (r'^ubuntu_linux$',     "Ubuntu", lambda m: None, "os"),
    (r'^debian_linux$',     "Debian", lambda m: None, "os"),
    (r'^linux_kernel$',     "Linux Kernel", lambda m: None, "os"),
    (r'^fedora$',           "Fedora", lambda m: None, "os"),
    (r'^centos$',           "CentOS", lambda m: None, "os"),
    (r'^opensuse$',         "openSUSE", lambda m: None, "os"),
    (r'^enterprise_linux$', "RHEL", lambda m: None, "os"),

    # ── VMware ───────────────────────────────────────────────────────
    (r'^esxi$',             "VMware ESXi", lambda m: None, "firmware"),
    (r'^vcenter_server$',   "vCenter Server", lambda m: None, "os"),

    # ── Apple ────────────────────────────────────────────────────────
    (r'^macos$',            "macOS", lambda m: None, "os"),
    (r'^mac_os_x$',         "Mac OS X", lambda m: None, "os"),
    (r'^iphone_os$',        "iOS", lambda m: None, "os"),

    # ── Android / Google ─────────────────────────────────────────────
    (r'^android$',          "Android", lambda m: None, "os"),

    # ── Firmware générique ────────────────────────────────────────────
    (r'^(.+)_firmware$',
     lambda m: m.group(1).replace("_", " ").title() + " Firmware",
     lambda m: None, "firmware"),
]

# Compile les patterns
COMPILED_RULES = [
    (re.compile(pattern, re.IGNORECASE), os_nom, version_fn, type_produit)
    for pattern, os_nom, version_fn, type_produit in NORMALIZATION_RULES
]


def normalize_product(nvd_vendor: str, nvd_product: str) -> dict | None:
    """
    Applique les règles de normalisation sur un couple (vendor, produit).
    Retourne un dict {os_nom, version, nvd_vendor, nvd_product, type_produit}
    ou None si aucune règle ne matche.
    """
    for pattern, os_nom_def, version_fn, type_produit in COMPILED_RULES:
        match = pattern.match(nvd_product)
        if match:
            # os_nom peut être une string ou un callable
            if callable(os_nom_def):
                os_nom = os_nom_def(match)
            else:
                os_nom = os_nom_def

            version = version_fn(match)
            if version:
                version = version.strip()

            return {
                "os_nom": os_nom,
                "version": version or None,
                "nvd_vendor": nvd_vendor,
                "nvd_product": nvd_product,
                "type_produit": type_produit,
            }
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Extrait les OS/versions depuis les CVE et peuple os_versions"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Affiche sans insérer en base")
    parser.add_argument("--verbose", action="store_true",
                        help="Affiche chaque entrée traitée")
    parser.add_argument("--vendor", type=str, default=None,
                        help="Limiter à un vendor spécifique (ex: microsoft)")
    args = parser.parse_args()

    logger.info("\n" + "=" * 65)
    logger.info("  EXTRACT OS VERSIONS — Depuis les CVE NVD")
    logger.info("=" * 65 + "\n")

    conn = get_connection()
    cur = conn.cursor()

    # ── Créer la table si elle n'existe pas ──────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS os_versions (
            id INT(11) NOT NULL AUTO_INCREMENT,
            os_nom VARCHAR(255) NOT NULL
                COMMENT 'Nom affiché : "Windows Server", "DSM", "FortiOS"',
            version VARCHAR(100) DEFAULT NULL
                COMMENT 'Version affichée : "2022", "24H2", "9.1.2"',
            nvd_vendor VARCHAR(255) NOT NULL
                COMMENT 'Vendor NVD exact : "microsoft", "synology"',
            nvd_product VARCHAR(255) NOT NULL
                COMMENT 'Produit NVD exact : "windows_server_2022"',
            type_produit ENUM('os','firmware','bios') DEFAULT 'os',
            created_at TIMESTAMP NULL DEFAULT current_timestamp(),
            PRIMARY KEY (id),
            UNIQUE KEY uq_nvd (nvd_vendor, nvd_product),
            KEY idx_os_nom (os_nom),
            KEY idx_nvd_vendor (nvd_vendor)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)
    conn.commit()
    logger.info("[TABLE] os_versions vérifiée/créée\n")

    # ── Charger les couples distincts (fabricant, produit) des CVE ───
    vendor_filter = "AND fabricant = %s" if args.vendor else ""
    query_params = [args.vendor] if args.vendor else []

    cur.execute(f"""
        SELECT DISTINCT fabricant, produit
        FROM cve
        WHERE fabricant IS NOT NULL
          AND produit IS NOT NULL
          {vendor_filter}
        ORDER BY fabricant, produit
    """, query_params)

    pairs = cur.fetchall()
    logger.info(f"Couples (fabricant, produit) distincts : {len(pairs)}\n")

    inserted = 0
    skipped = 0
    no_match = 0

    for row in pairs:
        vendor = row["fabricant"]
        product = row["produit"]

        entry = normalize_product(vendor, product)

        if entry is None:
            no_match += 1
            if args.verbose:
                logger.info(f"  [NO MATCH] {vendor} / {product}")
            continue

        if args.verbose:
            version_str = f" v{entry['version']}" if entry['version'] else ""
            logger.info(f"  [OK] {vendor}/{product}"
                  f" → {entry['os_nom']}{version_str}"
                  f" ({entry['type_produit']})")

        if not args.dry_run:
            cur.execute("""
                INSERT IGNORE INTO os_versions
                    (os_nom, version, nvd_vendor, nvd_product, type_produit)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                entry["os_nom"],
                entry["version"],
                entry["nvd_vendor"],
                entry["nvd_product"],
                entry["type_produit"],
            ))
            if cur.rowcount > 0:
                inserted += 1
            else:
                skipped += 1

    if not args.dry_run:
        conn.commit()

    conn.close()

    logger.info(f"\n{'='*65}")
    if args.dry_run:
        logger.info(f"  DRY-RUN — rien n'a été écrit en base")
    else:
        logger.info(f"  ✅ Insérés  : {inserted}")
        logger.info(f"  ⏭️  Ignorés  : {skipped} (déjà présents)")
    logger.info(f"  ❓ Sans règle : {no_match} produits non normalisés")
    logger.info(f"{'='*65}\n")

    if no_match > 0 and args.verbose:
        logger.info(
            f"→ Pour couvrir plus de produits, ajoute des règles dans NORMALIZATION_RULES")


if __name__ == "__main__":
    main()