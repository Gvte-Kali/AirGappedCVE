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

# ── Forcer le flush de stdout pour la console web ─────────────
import functools
print = functools.partial(print, flush=True)

# ── Configuration ──────────────────────────────────────────────
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

# ── Utilitaires ───────────────────────────────────────────────

def log(msg):
    """Log avec timestamp."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"  [{ts}] {msg}")

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
                # Parser la date et forcer le fuseau horaire UTC
                dt = datetime.fromisoformat(last_modified.replace("Z", "+00:00") if "Z" in last_modified else last_modified)
                # Si la date est naive (sans timezone), on l'associe à UTC
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

    # --- Lire la date de la dernière CVE dans le dernier fichier raw ---
    last_raw_file = get_last_raw_file()
    last_cve_date = None
    if last_raw_file:
        last_cve_date = get_last_cve_date_from_file(last_raw_file)
        if last_cve_date:
            log(f"Dernière CVE dans {last_raw_file.name}: {last_cve_date}")

    # --- Déterminer la plage de dates ---
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    params = {}

    if last_cve_date:
        delta_seconds = (now - last_cve_date).total_seconds()
        if delta_seconds < 60:
            log("Plage trop courte (<1min). Full sync sans filtre de date.")
        else:
            if delta_seconds > 120 * 24 * 3600:
                log(f"Plage trop grande ({int(delta_seconds//86400)} jours). Découpage en sous-plages de 30 jours.")
                # Découper en sous-plages de 30 jours
                date_ranges = []
                current_start = last_cve_date
                while current_start < now:
                    current_end = min(current_start + timedelta(days=30), now)
                    date_ranges.append((current_start, current_end))
                    current_start = current_end

                page = resume_page
                total_downloaded = start_index
                for i, (range_start, range_end) in enumerate(date_ranges):
                    sub_params = {
                        "lastModStartDate": range_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "lastModEndDate": range_end.strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                    log(f"Sous-plage {i+1}: {sub_params['lastModStartDate']} → {sub_params['lastModEndDate']}")

                    sub_start_index = 0
                    while True:
                        data = download_cve_page(sub_start_index, sub_params)
                        if not data:
                            log(f"✗ Échec pour la sous-plage {i+1} à startIndex={sub_start_index}")
                            return False

                        vulns = data.get("vulnerabilities", [])
                        if not vulns:
                            break

                        filename = RAW_DIR / f"cve_full_page_{page:04d}.json"
                        log(f"Écriture: {filename} ({len(vulns)} CVE)")
                        with open(filename, "w", encoding="utf-8") as f:
                            json.dump(data, f, ensure_ascii=False)

                        total_downloaded += len(vulns)
                        sub_start_index += len(vulns)
                        page += 1
                        time.sleep(DELAY)

                print(f"\n============================================================")
                print(f"  ✓ TÉLÉCHARGEMENT PAR SOUS-PLAGES TERMINÉ !")
                print(f"  → {total_downloaded:,} CVE en {page} pages")
                print(f"============================================================")
                return True
            else:
                params = {
                    "lastModStartDate": last_cve_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%SZ")
                }
                log(f"Plage de dates: {params['lastModStartDate']} → {params['lastModEndDate']}")
    else:
        log("Aucune date de dernière CVE trouvée. Full sync sans filtre de date.")

    print(f"============================================================")
    print(f"  MODE FULL — Toutes les CVE")
    print(f"  Délai entre requêtes: {DELAY}s")
    print(f"  Page de départ: {resume_page}")
    print(f"  startIndex de départ: {start_index}")
    print(f"============================================================")

    batch_start = time.time()

    # Première requête pour connaître le total
    log("Première requête pour connaître le total...")
    data = download_cve_page(start_index, params)
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

        data = download_cve_page(start_index, params)
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

    print(f"\n============================================================")
    print(f"  ✓ TÉLÉCHARGEMENT FULL TERMINÉ !")
    print(f"  → {total_downloaded:,} CVE en {page} pages")
    print(f"  → Durée: {elapsed_min}m{elapsed_sec:02d}s")
    print(f"============================================================")

    return True

# ── Téléchargement CWE ────────────────────────────────────────

def download_cwe():
    """Télécharge le fichier XML des CWE depuis MITRE."""
    import zipfile
    import io

    print(f"\n============================================================")
    print(f"  TÉLÉCHARGEMENT CWE (MITRE)")
    print(f"============================================================")

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
    print(f"============================================================")
    print(f"  SYNCHRONISATION NVD / CWE")
    print(f"  Démarrage: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Clé API NVD: {'OUI ✓' if NVD_API_KEY else 'NON ✗ (lent)'}")
    print(f"  Données: {BASE_DIR}/")
    print(f"  Python: {sys.version}")
    print(f"  PID: {os.getpid()}")
    print(f"============================================================")

    ensure_dirs()
    cve_ok = download_cve_full()
    cwe_ok = download_cwe()

    # Résumé final
    print(f"\n============================================================")
    print(f"  RÉSUMÉ FINAL")
    print(f"  CVE: {'✓ OK' if cve_ok else '✗ ERREUR'}")
    print(f"  CWE: {'✓ OK' if cwe_ok else '✗ ERREUR'}")
    print(f"  Fin: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"============================================================")

    return 0 if (cve_ok and cwe_ok) else 1

if __name__ == "__main__":
    sys.exit(main())