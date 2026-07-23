#!/usr/bin/env python3
"""
Téléchargement des données NVD (CVE) et MITRE (CWE).
Ne touche PAS à la base de données. Stocke les fichiers bruts sur disque.
"""

import os
import sys
import json
import time
import glob
import re
import requests
from pathlib import Path
from datetime import datetime, timezone, timedelta
import logging

# ── Configuration du logging ─────────────────────────────────────
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "download_nvd.log")
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

# Configurer le logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# ── Configuration ──────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent / "data" / "nvd"
RAW_DIR = BASE_DIR / "raw"
CWE_DIR = BASE_DIR / "cwe"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
PAGE_SIZE = 2000
DELAY_WITH_KEY = 0.6
DELAY_WITHOUT_KEY = 6.0
MAX_RETRIES = 5
RETRY_DELAY = 10

DELAY = DELAY_WITH_KEY if NVD_API_KEY else DELAY_WITHOUT_KEY

# ── Utilitaires ────────────────────────────────────────────────────

def log(msg):
    """Log avec timestamp."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    logger.info(f"  [{ts}] {msg}")

def ensure_dirs():
    """Crée les répertoires nécessaires."""
    log(f"Vérification répertoire RAW: {RAW_DIR}")
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    log(f"Vérification répertoire CWE: {CWE_DIR}")
    CWE_DIR.mkdir(parents=True, exist_ok=True)
    log("Répertoires OK ✓")

def count_existing_full_pages():
    """Compte les fichiers cve_full_page_*.json et retourne le nombre et le plus grand index."""
    pattern = str(RAW_DIR / "cve_full_page_*.json")
    log(f"Recherche fichiers existants: {pattern}")
    files = glob.glob(pattern)
    log(f"Fichiers trouvés: {len(files)}")

    if not files:
        return 0, -1

    max_index = -1
    for f in files:
        match = re.search(r'cve_full_page_(\d+)\.json', f)
        if match:
            idx = int(match.group(1))
            if idx > max_index:
                max_index = idx
            log(f"  → {os.path.basename(f)} (index={idx})")

    log(f"Plus grand index: {max_index}")
    return len(files), max_index

def get_last_raw_file():
    """Retourne le chemin du dernier fichier cve_*_page_*.json."""
    files = glob.glob(str(RAW_DIR / "cve_*_page_*.json"))
    if not files:
        return None
    return Path(max(files, key=lambda f: int(re.search(r'cve_\w+_page_(\d+)\.json', f).group(1))))

def get_last_cve_date_from_file(file_path):
    """Retourne la date de la dernière CVE dans le fichier JSON (toujours en UTC)."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            last_modified = vulns[-1].get("cve", {}).get("lastModified")
            if last_modified:
                dt = datetime.fromisoformat(last_modified.replace("Z", "+00:00") if "Z" in last_modified else last_modified)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
    except Exception:
        return None
    return None

def print_progress(downloaded, total, start_time, page):
    """Affiche la progression."""
    elapsed = time.time() - start_time
    if elapsed > 0 and downloaded > 0:
        rate = downloaded / elapsed
        remaining = (total - downloaded) / rate if rate > 0 else 0
        remaining_min = int(remaining // 60)
        remaining_sec = int(remaining % 60)
        time_str = f"~{remaining_min}m{remaining_sec:02d}s restant"
        rate_str = f"{rate:.0f} CVE/s"
    else:
        time_str = "calcul..."
        rate_str = "..."

    pct = (downloaded / total * 100) if total > 0 else 0
    bar_len = 30
    filled = int(bar_len * downloaded // total) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_len - filled)
    log(f"[{bar}] {downloaded:,}/{total:,} ({pct:.1f}%) | page {page} | {rate_str} | {time_str}")

# ── Téléchargement CVE ────────────────────────────────────────

def download_cve_page(start_index, params):
    """Télécharge une page de résultats CVE depuis l'API NVD avec retry."""
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    request_params = {**params, "startIndex": start_index, "resultsPerPage": PAGE_SIZE}

    for attempt in range(1, MAX_RETRIES + 1):
        log(f"Requête API: startIndex={start_index}, pageSize={PAGE_SIZE} (tentative {attempt}/{MAX_RETRIES})")

        try:
            log(f"Envoi requête GET vers {NVD_API_URL}...")
            resp = requests.get(NVD_API_URL, params=request_params, headers=headers, timeout=60)
            log(f"Réponse reçue: HTTP {resp.status_code} ({len(resp.content):,} octets)")

            if resp.status_code == 200:
                data = resp.json()
                nb_vulns = len(data.get("vulnerabilities", []))
                total = data.get("totalResults", "?")
                log(f"✓ Page OK: {nb_vulns} CVE dans cette page, total={total}")
                return data

            elif resp.status_code == 403:
                wait = RETRY_DELAY * attempt * 2
                log(f"⚠ 403 Forbidden — rate limit probable. Attente {wait}s...")
                time.sleep(wait)

            elif resp.status_code == 503:
                wait = RETRY_DELAY * attempt
                log(f"⚠ 503 Service indisponible. Attente {wait}s...")
                time.sleep(wait)

            else:
                log(f"✗ Erreur HTTP {resp.status_code}: {resp.text[:200]}")
                time.sleep(RETRY_DELAY)

        except requests.exceptions.Timeout:
            log(f"⚠ Timeout après 60s (tentative {attempt}/{MAX_RETRIES})")
            time.sleep(RETRY_DELAY)

        except requests.exceptions.ConnectionError as e:
            log(f"⚠ Erreur connexion: {e}")
            time.sleep(RETRY_DELAY * 2)

        except Exception as e:
            log(f"✗ Erreur inattendue: {type(e).__name__}: {e}")
            time.sleep(RETRY_DELAY)

    log(f"✗ ÉCHEC DÉFINITIF après {MAX_RETRIES} tentatives pour startIndex={start_index}")
    return None

def download_cve_full():
    """Télécharge toutes les CVE. Reprend là où ça s'est arrêté."""
    # Vérifier les pages existantes
    nb_files, max_index = count_existing_full_pages()

    if nb_files > 0:
        resume_page = max_index
        start_index = resume_page * PAGE_SIZE
        log(f"REPRISE: {nb_files} fichier(s), dernier index={max_index}")
        log(f"Re-téléchargement depuis page {resume_page} (startIndex={start_index})")
    else:
        resume_page = 0
        start_index = 0
        log("DÉPART À ZÉRO: aucun fichier existant")

    # Mode FULL : toujours télécharger toutes les pages à partir de start_index
    log("Mode FULL — Toutes les CVE depuis startIndex")
    log(f"Délai entre requêtes: {DELAY}s")

    batch_start = time.time()

    # Première requête pour connaître le total
    log("Première requête pour connaître le total...")
    data = download_cve_page(start_index, {})
    if not data:
        log("✗ FATAL: Impossible de contacter l'API NVD. Abandon.")
        return False

    total_results = data.get("totalResults", 0)
    log(f"TOTAL CVE DISPONIBLES: {total_results:,}")

    if total_results == 0:
        log("Aucune CVE disponible (!?). Fin.")
        return True

    # CVE déjà téléchargées dans les pages précédentes
    already_downloaded = resume_page * PAGE_SIZE
    total_downloaded = already_downloaded
    log(f"CVE déjà comptabilisées (pages précédentes): {already_downloaded:,}")

    # Sauvegarder la première page
    vulns = data.get("vulnerabilities", [])
    page = resume_page
    filename = RAW_DIR / f"cve_full_page_{page:04d}.json"
    log(f"Écriture: {filename} ({len(vulns)} CVE)")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)

    total_downloaded += len(vulns)
    print_progress(total_downloaded, total_results, batch_start, page)

    start_index += len(vulns)
    page += 1

    # Boucle sur les pages suivantes
    while start_index < total_results:
        log(f"Attente {DELAY}s avant prochaine requête...")
        time.sleep(DELAY)

        data = download_cve_page(start_index, {})
        if not data:
            log(f"✗ ERREUR à startIndex={start_index}. Arrêt.")
            log(f"→ {page} pages sauvegardées. Relancez pour reprendre.")
            return False

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            log("Page vide reçue. Fin du téléchargement.")
            break

        # Sauvegarder
        filename = RAW_DIR / f"cve_full_page_{page:04d}.json"
        log(f"Écriture: {filename} ({len(vulns)} CVE)")
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

        total_downloaded += len(vulns)
        print_progress(total_downloaded, total_results, batch_start, page)

        start_index += len(vulns)
        page += 1

    # Terminé !
    elapsed = time.time() - batch_start
    elapsed_min = int(elapsed // 60)
    elapsed_sec = int(elapsed % 60)

    logger.info(f"\n===========================================================")
    logger.info(f"  ✓ TÉLÉCHARGEMENT FULL TERMINÉ !")
    logger.info(f"  → {total_downloaded:,} CVE en {page} pages")
    logger.info(f"  → Durée: {elapsed_min}m{elapsed_sec:02d}s")
    logger.info(f"===========================================================")

    # Vérification finale : la dernière CVE téléchargée est-elle récente ?
    last_file = get_last_raw_file()
    if last_file:
        last_cve_date = get_last_cve_date_from_file(last_file)
        if last_cve_date:
            age_hours = (datetime.now(timezone.utc) - last_cve_date).total_seconds() / 3600
            logger.info(f"Dernière CVE téléchargée : {last_cve_date} (il y a {age_hours:.1f} heures)")
            if age_hours > 24:
                logger.warning("⚠ La dernière CVE a plus de 24h. Vérifiez que le téléchargement est complet.")

    return True

# ── Téléchargement CWE ────────────────────────────────────────

def download_cwe():
    """Télécharge le fichier XML des CWE depuis MITRE."""
    import zipfile
    import io

    logger.info(f"\n===========================================================")
    logger.info(f"  TÉLÉCHARGEMENT CWE (MITRE)")
    logger.info(f"===========================================================")

    target = CWE_DIR / "cwec_latest.xml"

    log(f"URL: {CWE_URL}")
    log(f"Destination: {target}")
    log("Envoi requête...")

    try:
        resp = requests.get(CWE_URL, timeout=120)
        log(f"Réponse: HTTP {resp.status_code} ({len(resp.content):,} octets)")

        if resp.status_code != 200:
            log(f"✗ Erreur HTTP {resp.status_code}")
            return False

        log("Décompression ZIP...")
        z = zipfile.ZipFile(io.BytesIO(resp.content))
        xml_files = [n for n in z.namelist() if n.endswith('.xml')]
        log(f"Fichiers dans le ZIP: {z.namelist()}")

        if not xml_files:
            log("✗ Pas de fichier XML dans l'archive")
            return False

        xml_content = z.read(xml_files[0])
        log(f"Écriture: {target} ({len(xml_content) / 1024 / 1024:.1f} Mo)")
        with open(target, "wb") as f:
            f.write(xml_content)

        log("✓ CWE téléchargé avec succès")
        return True

    except Exception as e:
        log(f"✗ Erreur: {type(e).__name__}: {e}")
        return False

# ── Point d'entrée ────────────────────────────────────────────

def main():
    logger.info(f"===========================================================")
    logger.info(f"  SYNCHRONISATION NVD / CWE")
    logger.info(f"  Démarrage: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    logger.info(f"  Clé API NVD: {'OUI ✓' if NVD_API_KEY else 'NON ✗ (lent)'}")
    logger.info(f"  Données: {BASE_DIR}/")
    logger.info(f"  Python: {sys.version}")
    logger.info(f"  PID: {os.getpid()}")
    logger.info(f"===========================================================")

    ensure_dirs()
    cve_ok = download_cve_full()
    cwe_ok = download_cwe()

    # Résumé final
    logger.info(f"\n===========================================================")
    logger.info(f"  RÉSUMÉ FINAL")
    logger.info(f"  CVE: {'✓ OK' if cve_ok else '✗ ERREUR'}")
    logger.info(f"  CWE: {'✓ OK' if cwe_ok else '✗ ERREUR'}")
    logger.info(f"  Fin: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    logger.info(f"===========================================================")

    return 0 if (cve_ok and cwe_ok) else 1

if __name__ == "__main__":
    sys.exit(main())