#!/usr/bin/env python3
"""
sync_all.py — Script consolidé pour synchroniser toutes les données CVE

Ordre d'exécution :
1. download_nvd.py - Télécharge les données NVD et CWE
2. import_vendors_models.py - Import les vendors et modèles depuis les fichiers NVD
3. cve_sync.py - Synchronise les CVE dans la base de données
4. extract_os_versions.py - Extrait les versions OS depuis les CVE

Usage:
    python3 scripts/sync_all.py
    python3 scripts/sync_all.py --verbose
    python3 scripts/sync_all.py --dry-run
"""

import argparse
import glob
import json
import os
import re
import sys
import time
import zipfile
import io
from datetime import datetime, timezone
from pathlib import Path

# Local imports
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from database import get_connection

# Force flush for web console
import functools
print = functools.partial(print, flush=True)

# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_DIR = Path(_PROJECT_ROOT) / "data" / "nvd"
RAW_DIR = BASE_DIR / "raw"
CWE_DIR = BASE_DIR / "cwe"
STATE_FILE = BASE_DIR / "sync_state.json"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
PAGE_SIZE = 2000
DELAY_WITH_KEY = 0.6
DELAY_WITHOUT_KEY = 6.0
MAX_RETRIES = 5
RETRY_DELAY = 10

DELAY = DELAY_WITH_KEY if NVD_API_KEY else DELAY_WITHOUT_KEY

# =============================================================================
# PROGRESS BAR & LOGGING
# =============================================================================

class ProgressBar:
    """Beautiful progress bar with ETA and rate"""
    def __init__(self, total, description="", bar_length=40):
        self.total = total
        self.current = 0
        self.description = description
        self.bar_length = bar_length
        self.start_time = time.time()
        self.last_update = 0
        self.min_update_interval = 0.1

    def update(self, current, description=None):
        now = time.time()
        if now - self.last_update < self.min_update_interval and current < self.total:
            return
        self.current = current
        if description:
            self.description = description
        self._display()
        self.last_update = now

    def _display(self):
        if self.total == 0:
            pct, filled = 0, 0
        else:
            pct = (self.current / self.total) * 100
            filled = int(self.bar_length * self.current / self.total)
        bar = "█" * filled + "░" * (self.bar_length - filled)
        elapsed = time.time() - self.start_time
        if elapsed > 0 and self.current > 0 and self.total > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            time_str = f"~{int(remaining//60)}m{int(remaining%60):02d}s"
            rate_str = f"{rate:.0f}/s"
        else:
            time_str, rate_str = "calcul...", "..."
        desc = f"{self.description}: " if self.description else ""
        sys.stdout.write(f"\r{desc}[{bar}] {self.current:,}/{self.total:,} ({pct:.1f}%) | {rate_str} | {time_str}")
        sys.stdout.flush()

    def finish(self):
        self.current = self.total
        self._display()
        print()

    def __enter__(self):
        self.start_time = time.time()
        self.last_update = 0
        return self

    def __exit__(self, *args):
        self.finish()

class StepLogger:
    """Context-aware logger with timestamps"""
    def __init__(self, step_name):
        self.step_name = step_name
        self.start_time = datetime.now(timezone.utc)

    def log(self, msg, level="INFO"):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        symbol = {"INFO":"ℹ", "SUCCESS":"✓", "WARNING":"⚠", "ERROR":"✗"}.get(level, "•")
        print(f"[{ts}] [{self.step_name}] {symbol} {msg}")

    def success(self, msg): self.log(msg, "SUCCESS")
    def warning(self, msg): self.log(msg, "WARNING")
    def error(self, msg): self.log(msg, "ERROR")

# =============================================================================
# DOWNLOAD NVD FUNCTIONS
# =============================================================================

def ensure_dirs():
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    CWE_DIR.mkdir(parents=True, exist_ok=True)

def load_state():
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)

def count_existing_full_pages():
    files = glob.glob(str(RAW_DIR / "cve_full_page_*.json"))
    if not files:
        return 0, -1
    max_idx = max(int(re.search(r'cve_full_page_(\d+)\.json', f).group(1)) for f in files if re.search(r'cve_full_page_(\d+)\.json', f))
    return len(files), max_idx

def download_cve_page(start_index, params, logger):
    import requests
    import urllib.parse
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            full_params = {**params, "startIndex": start_index, "resultsPerPage": PAGE_SIZE}
            resp = requests.get(
                NVD_API_URL,
                params=full_params,
                headers=headers,
                timeout=60
            )
            full_url = f"{NVD_API_URL}?{urllib.parse.urlencode(full_params)}"

            if resp.status_code == 200:
                data = resp.json()
                logger.log(f"Page OK: {len(data.get('vulnerabilities',[]))} CVE, total={data.get('totalResults','?')}")
                return data
            elif resp.status_code == 404:
                # L'API retourne 404 si AUCUNE CVE n'est trouvée dans la plage
                logger.log(f"HTTP 404: Aucune CVE trouvée pour cette plage de dates (URL: {full_url})")
                return {"vulnerabilities": [], "totalResults": 0}  # <-- Retourne un objet vide au lieu de None
            elif resp.status_code in (403, 503, 500, 429):
                retry_after = int(resp.headers.get("Retry-After", 10)) if resp.status_code == 429 else RETRY_DELAY * attempt
                logger.warning(f"HTTP {resp.status_code} (attempt {attempt}/{MAX_RETRIES}) | Retry after: {retry_after}s")
                time.sleep(retry_after)
            else:
                logger.warning(f"HTTP {resp.status_code} (attempt {attempt}/{MAX_RETRIES}) | URL: {full_url}")
                time.sleep(RETRY_DELAY)
        except Exception as e:
            logger.warning(f"Attempt {attempt}/{MAX_RETRIES}: {e}")
            time.sleep(RETRY_DELAY)
    return None

def download_cve_full(logger):
    state = load_state()
    nb_files, max_index = count_existing_full_pages()
    start_index = (max_index * PAGE_SIZE) if nb_files > 0 else 0
    logger.log(f"{'RESUMING' if nb_files > 0 else 'STARTING FROM SCRATCH'}: {nb_files} files, last index={max_index}")

    data = download_cve_page(start_index, {}, logger)
    if not data:
        logger.error("FATAL: Cannot contact NVD API")
        return False

    total_results = data.get("totalResults", 0)
    logger.log(f"TOTAL CVE: {total_results:,}")
    if total_results == 0:
        return True

    total_downloaded = (max_index * PAGE_SIZE) if nb_files > 0 else 0
    page = max_index if nb_files > 0 else 0

    # Save first page
    vulns = data.get("vulnerabilities", [])
    with open(RAW_DIR / f"cve_full_page_{page:04d}.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    total_downloaded += len(vulns)
    state.update({"mode":"full", "total_results":total_results, "last_page_downloaded":page,
                 "total_downloaded":total_downloaded, "last_update":datetime.now(timezone.utc).isoformat()})
    save_state(state)

    start_index += len(vulns)
    page += 1

    with ProgressBar(total_results, "Downloading CVE") as pbar:
        pbar.update(total_downloaded)
        while start_index < total_results:
            time.sleep(DELAY)
            data = download_cve_page(start_index, {}, logger)
            if not data:
                state["error"] = f"Stopped at {start_index}"
                save_state(state)
                return False
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            with open(RAW_DIR / f"cve_full_page_{page:04d}.json", "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            total_downloaded += len(vulns)
            pbar.update(total_downloaded, f"Page {page}")
            state.update({"last_page_downloaded":page, "total_downloaded":total_downloaded,
                         "last_update":datetime.now(timezone.utc).isoformat()})
            if "error" in state:
                del state["error"]
            save_state(state)
            start_index += len(vulns)
            page += 1

    state.update({"last_cve_sync":datetime.now(timezone.utc).isoformat(), "full_complete":True,
                 "last_page_downloaded":page-1, "total_downloaded":total_downloaded,
                 "last_update":datetime.now(timezone.utc).isoformat()})
    save_state(state)
    logger.success(f"FULL DOWNLOAD COMPLETE! {total_downloaded:,} CVE in {page} pages")
    return True

def download_cve_incremental(last_sync, logger):
    logger.log(f"INCREMENTAL MODE — Since {last_sync}")
    for f in glob.glob(str(RAW_DIR / "cve_delta_page_*.json")):
        os.remove(f)

    # Corriger le format de date pour l'API NVD (ajouter les millisecondes)
    last_sync_dt = datetime.fromisoformat(last_sync.replace("Z", "+00:00")) if "Z" in last_sync else datetime.fromisoformat(last_sync)
    last_mod_end_date = datetime.now(timezone.utc)
    # Limiter la plage à 120 jours max (limite de l'API NVD)
    if (last_mod_end_date - last_sync_dt).days > 120:
        last_sync_dt = last_mod_end_date - timedelta(days=120)
        logger.warning(f"Limiting start date to 120 days ago: {last_sync_dt}")

    params = {
    "lastModStartDate": last_sync_dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z",
    "lastModEndDate": last_mod_end_date.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
}
    logger.log(f"Requesting CVE modified between {params['lastModStartDate']} and {params['lastModEndDate']}")  # Debug
    data = download_cve_page(0, params, logger)
    if not data:
        return False

    total_results = data.get("totalResults", 0)
    if total_results == 0:
        state = load_state()
        state.update({"last_cve_sync": datetime.now(timezone.utc).isoformat(), "last_update": datetime.now(timezone.utc).isoformat()})
        save_state(state)
        logger.log("No new CVE found in the date range.")
        return True

    total_downloaded = 0
    page = 0
    with ProgressBar(total_results, "Downloading delta") as pbar:
        while True:
            vulns = data.get("vulnerabilities", [])
            with open(RAW_DIR / f"cve_delta_page_{page:04d}.json", "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            total_downloaded += len(vulns)
            pbar.update(total_downloaded, f"Page {page}")
            state = load_state()
            state.update({"delta_pages": page, "delta_downloaded": total_downloaded, "last_update": datetime.now(timezone.utc).isoformat()})
            save_state(state)
            if len(vulns) < PAGE_SIZE:
                break
            time.sleep(DELAY)
            page += 1
            data = download_cve_page(page * PAGE_SIZE, params, logger)
            if not data:
                return False

    state = load_state()
    state.update({"last_cve_sync": datetime.now(timezone.utc).isoformat(), "last_update": datetime.now(timezone.utc).isoformat()})
    save_state(state)
    logger.success(f"INCREMENTAL SYNC COMPLETE! {total_downloaded:,} CVE")
    return True

def download_cwe(logger):
    import requests
    logger.log(f"Downloading CWE from {CWE_URL}")
    try:
        resp = requests.get(CWE_URL, timeout=120)
        if resp.status_code != 200:
            logger.error(f"HTTP {resp.status_code}")
            return False
        z = zipfile.ZipFile(io.BytesIO(resp.content))
        xml_files = [n for n in z.namelist() if n.endswith('.xml')]
        if not xml_files:
            return False
        with open(CWE_DIR / "cwec_latest.xml", "wb") as f:
            f.write(z.read(xml_files[0]))
        state = load_state()
        state.update({"last_cwe_sync":datetime.now(timezone.utc).isoformat(), "last_update":datetime.now(timezone.utc).isoformat()})
        save_state(state)
        logger.success("CWE downloaded successfully")
        return True
    except Exception as e:
        logger.error(f"Error: {e}")
        return False

# =============================================================================
# IMPORT VENDORS MODELS FUNCTIONS
# =============================================================================

CPE_PART_MAP = {"a": "application", "o": "os", "h": "hardware"}

def parse_cpe(cpe_string):
    parts = cpe_string.split(":")
    if len(parts) < 5:
        return None
    cpe_part, nvd_vendor, nvd_product = parts[2].strip(), parts[3].strip(), parts[4].strip()
    if not nvd_vendor or nvd_vendor in ("*", "-") or not nvd_product or nvd_product in ("*", "-"):
        return None
    return {
        "nvd_vendor": nvd_vendor, "nom_vendor": nvd_vendor.replace("_", " ").title(),
        "nvd_product": nvd_product, "nom_product": nvd_product.replace("_", " ").title(),
        "cpe_part": cpe_part if cpe_part in ("a", "o", "h") else "a",
        "type_produit": CPE_PART_MAP.get(cpe_part, "application"),
        "cpe_base": f"cpe:2.3:{cpe_part}:{nvd_vendor}:{nvd_product}"
    }

def extract_pairs_from_file(json_path, logger):
    seen = set()
    results = []
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        for vuln in data.get("vulnerabilities", []):
            for config in vuln.get("cve", {}).get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        parsed = parse_cpe(match.get("criteria", ""))
                        if parsed:
                            key = (parsed["nvd_vendor"], parsed["nvd_product"])
                            if key not in seen:
                                seen.add(key)
                                results.append(parsed)
    except Exception as e:
        logger.warning(f"Cannot read {json_path.name}: {e}")
    return results

def import_vendors_models(raw_dir, logger, batch_size=100):
    raw_path = Path(raw_dir)
    if not raw_path.exists():
        logger.error(f"Directory not found: {raw_dir}")
        return False

    json_files = sorted(raw_path.glob("*.json"))
    if not json_files:
        logger.error(f"No JSON files in {raw_dir}")
        return False

    logger.log(f"Processing {len(json_files)} files...")

    # Étape 1: Extraction
    all_entries = []
    seen_global = set()

    with ProgressBar(len(json_files), "Extracting CPE") as pbar:
        for i, jf in enumerate(json_files, 1):
            entries = extract_pairs_from_file(jf, logger)
            new = 0
            for e in entries:
                key = (e["nvd_vendor"], e["nvd_product"])
                if key not in seen_global:
                    seen_global.add(key)
                    all_entries.append(e)
                    new += 1
            pbar.update(i, f"{jf.name} (+{new})")

    if not all_entries:
        logger.warning("No CPE entries found!")
        return True

    unique_vendors = list({e["nvd_vendor"]: e for e in all_entries}.values())
    logger.success(f"Extracted {len(all_entries)} pairs, {len(unique_vendors)} unique vendors")

    # Étape 2: Charger TOUS les vendors existants en mémoire
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Charger tous les vendors d'un coup
            cur.execute("SELECT id, nvd_vendor FROM product_vendors")
            all_vendor_ids = {row["nvd_vendor"]: row["id"] for row in cur.fetchall()}
            logger.log(f"Loaded {len(all_vendor_ids)} vendor IDs from database")

            # Insert vendors par batches
            vendors_inserted = 0
            with ProgressBar(len(unique_vendors), "Inserting vendors") as pbar:
                for i in range(0, len(unique_vendors), batch_size):
                    batch = unique_vendors[i:i+batch_size]
                    try:
                        cur.executemany(
                            "INSERT IGNORE INTO product_vendors (nom, nvd_vendor) VALUES (%s, %s)",
                            [(v["nom_vendor"], v["nvd_vendor"]) for v in batch]
                        )
                        vendors_inserted += cur.rowcount
                        conn.commit()
                    except Exception as e:
                        logger.warning(f"Vendor batch failed: {e}")
                        conn.rollback()
                    pbar.update(i + len(batch))

            logger.success(f"Vendors: {vendors_inserted} inserted, {len(unique_vendors) - vendors_inserted} existed")

            # Étape 3: Insertion des models
            models_inserted = 0
            with ProgressBar(len(all_entries), "Inserting models") as pbar:
                for i in range(0, len(all_entries), batch_size):
                    batch = all_entries[i:i+batch_size]

                    # Utiliser le cache all_vendor_ids
                    rows = []
                    for m in batch:
                        vid = all_vendor_ids.get(m["nvd_vendor"])
                        if vid is None:
                            # Vendor n'existe pas encore, on le crée
                            try:
                                cur.execute(
                                    "INSERT IGNORE INTO product_vendors (nom, nvd_vendor) VALUES (%s, %s)",
                                    (m["nom_vendor"], m["nvd_vendor"])
                                )
                                conn.commit()
                                # Recharger l'ID
                                cur.execute("SELECT id FROM product_vendors WHERE nvd_vendor = %s", (m["nvd_vendor"],))
                                row = cur.fetchone()
                                if row:
                                    vid = row["id"]
                                    all_vendor_ids[m["nvd_vendor"]] = vid
                                else:
                                    logger.warning(f"Could not create vendor: {m['nvd_vendor']}")
                                    continue
                            except Exception as e:
                                logger.warning(f"Failed to create vendor {m['nvd_vendor']}: {e}")
                                continue

                        rows.append((
                            vid,
                            m["nom_product"],
                            m["nvd_product"],
                            m["cpe_part"],
                            m["type_produit"],
                            m["cpe_base"]
                        ))

                    # Insérer les models
                    if rows:
                        try:
                            cur.executemany("""
                                INSERT IGNORE INTO product_models
                                (vendor_id, nom, nvd_product, cpe_part, type_produit, cpe_base)
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """, rows)
                            models_inserted += cur.rowcount
                            conn.commit()
                        except Exception as e:
                            logger.error(f"Model batch failed: {e}")
                            conn.rollback()
                            # Essayer un par un
                            for row in rows:
                                try:
                                    cur.execute("""
                                        INSERT IGNORE INTO product_models
                                        (vendor_id, nom, nvd_product, cpe_part, type_produit, cpe_base)
                                        VALUES (%s, %s, %s, %s, %s, %s)
                                    """, row)
                                    models_inserted += cur.rowcount
                                    conn.commit()
                                except Exception as inner_e:
                                    logger.warning(f"Single model failed: {row[2]} - {inner_e}")
                    pbar.update(i + len(batch))

            logger.success(f"Models: {models_inserted} inserted, {len(all_entries) - models_inserted} existed")
            return True

    except Exception as e:
        logger.error(f"Fatal SQL Error: {e}")
        import traceback
        traceback.print_exc()
        conn.rollback()
        return False
    finally:
        conn.close()

# =============================================================================
# CVE SYNC FUNCTIONS
# =============================================================================

def load_filters(conn, logger):
    with conn.cursor() as cur:
        cur.execute("SELECT id, nvd_vendor FROM product_vendors")
        vendors = {row["id"]: row["nvd_vendor"] for row in cur.fetchall()}
        cur.execute("SELECT pv.nvd_vendor, pm.nvd_product FROM product_models pm JOIN product_vendors pv ON pm.vendor_id = pv.id")
        models = cur.fetchall()
    vendor_products = {}
    vendors_with_models = set()
    for row in models:
        vendor_products.setdefault(row["nvd_vendor"], set()).add(row["nvd_product"])
        vendors_with_models.add(row["nvd_vendor"])
    vendor_all = {vname for vid, vname in vendors.items() if vname not in vendors_with_models}
    logger.log(f"Filters: {len(vendor_all)} full vendors, {len(vendor_products)} with products")
    return vendor_all, vendor_products

def parse_cpe_sync(cpe_string):
    parts = cpe_string.split(":")
    if len(parts) >= 6:
        return parts[3].lower(), parts[4].lower(), parts[5] if parts[5] != "*" else None
    return None, None, None

def cve_matches_filters(cve_data, vendor_all, vendor_products):
    matched = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                cpe_str = cpe_match.get("criteria", "")
                vendor, product, version = parse_cpe_sync(cpe_str)
                if vendor is None:
                    continue
                if vendor in vendor_all or (vendor in vendor_products and product in vendor_products[vendor]):
                    matched.append({"cpe": cpe_str, "vendor": vendor, "product": product, "version": version,
                                   "version_start_including": cpe_match.get("versionStartIncluding"),
                                   "version_start_excluding": cpe_match.get("versionStartExcluding"),
                                   "version_end_including": cpe_match.get("versionEndIncluding"),
                                   "version_end_excluding": cpe_match.get("versionEndExcluding")})
    return matched

def extract_cve_info(cve_item, matched_cpes):
    cve_id = cve_item.get("id", "")
    description = next((d.get("value","") for d in cve_item.get("descriptions",[]) if d.get("lang")=="en"), "")
    metrics = cve_item.get("metrics", {})
    cvss3_score = cvss3_severity = cvss3_vector = None
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if key in metrics and metrics[key]:
            cd = metrics[key][0].get("cvssData", {})
            cvss3_score, cvss3_severity, cvss3_vector = cd.get("baseScore"), cd.get("baseSeverity"), cd.get("vectorString")
            break
    cvss2_score = None
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cvss2_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")
    cwes = [d["value"] for w in cve_item.get("weaknesses",[]) for d in w.get("description",[]) if d.get("value","").startswith("CWE-")]
    fabricant = matched_cpes[0]["vendor"] if matched_cpes else None
    produit = matched_cpes[0]["product"] if matched_cpes else None
    versions_affectees = [{"cpe":c["cpe"],"vendor":c["vendor"],"product":c["product"],"version_exact":c["version"],
                          "version_start_including":c["version_start_including"],"version_start_excluding":c["version_start_excluding"],
                          "version_end_including":c["version_end_including"],"version_end_excluding":c["version_end_excluding"]} for c in matched_cpes]
    return {"cve_id":cve_id,"description":description,"cvss_v3_score":cvss3_score,"cvss_v3_severity":cvss3_severity,
            "cvss_v3_vector":cvss3_vector,"cvss_v2_score":cvss2_score,"fabricant":fabricant,"produit":produit,
            "versions_affectees":json.dumps(versions_affectees),"cpe_affected":json.dumps([c["cpe"] for c in matched_cpes]),
            "date_publication":cve_item.get("published"),"date_modification":cve_item.get("lastModified"),
            "source_url":cve_item.get("references",[{}])[0].get("url"),"cwes":cwes}

def upsert_cve(conn, cve_info):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO cve (cve_id,description,cvss_v3_score,cvss_v3_severity,cvss_v3_vector,cvss_v2_score,fabricant,produit,
            versions_affectees,cpe_affected,date_publication,date_modification,source_url) VALUES
            (%(cve_id)s,%(description)s,%(cvss_v3_score)s,%(cvss_v3_severity)s,%(cvss_v3_vector)s,%(cvss_v2_score)s,
            %(fabricant)s,%(produit)s,%(versions_affectees)s,%(cpe_affected)s,%(date_publication)s,%(date_modification)s,%(source_url)s)
            ON DUPLICATE KEY UPDATE description=VALUES(description),cvss_v3_score=VALUES(cvss_v3_score),
            cvss_v3_severity=VALUES(cvss_v3_severity),cvss_v3_vector=VALUES(cvss_v3_vector),cvss_v2_score=VALUES(cvss_v2_score),
            fabricant=VALUES(fabricant),produit=VALUES(produit),versions_affectees=VALUES(versions_affectees),
            cpe_affected=VALUES(cpe_affected),date_publication=VALUES(date_publication),
            date_modification=VALUES(date_modification),source_url=VALUES(source_url)""", cve_info)
        for cwe_id in cve_info.get("cwes",[]):
            cur.execute("INSERT IGNORE INTO cve_cwe (cve_id,cwe_id) VALUES (%s,%s)", (cve_info["cve_id"], cwe_id))
        conn.commit()

def process_file(filepath, conn, vendor_all, vendor_products, stats):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return
    for vuln in data.get("vulnerabilities", []):
        cve_item = vuln.get("cve", {})
        matched_cpes = cve_matches_filters(cve_item, vendor_all, vendor_products)
        if not matched_cpes:
            stats["skipped"] += 1
            continue
        cve_info = extract_cve_info(cve_item, matched_cpes)
        upsert_cve(conn, cve_info)
        stats["imported"] += 1
    conn.commit()

def cve_sync(nvd_dir, logger):
    if not os.path.isdir(nvd_dir):
        logger.error(f"Directory not found: {nvd_dir}")
        return False
    json_files = sorted(glob.glob(os.path.join(nvd_dir, "*.json")))
    if not json_files:
        logger.error(f"No JSON files in {nvd_dir}")
        return False
    logger.log(f"Found {len(json_files)} files")
    conn = get_connection()
    try:
        vendor_all, vendor_products = load_filters(conn, logger)
        if not vendor_all and not vendor_products:
            logger.error("No vendors/products in database")
            return False
        stats = {"total_cve":0, "imported":0, "skipped":0}
        with ProgressBar(len(json_files), "Processing CVE") as pbar:
            for i, filepath in enumerate(json_files, 1):
                process_file(filepath, conn, vendor_all, vendor_products, stats)
                pbar.update(i, os.path.basename(filepath))
        logger.success(f"Results: {stats['total_cve']} processed, {stats['imported']} imported, {stats['skipped']} skipped")
        return True
    except Exception as e:
        logger.error(f"Error: {e}")
        return False
    finally:
        conn.close()

# =============================================================================
# EXTRACT OS VERSIONS FUNCTIONS
# =============================================================================

NORMALIZATION_RULES = [
    # Règles pour Windows (avec versions par défaut si absentes)
    (r'^windows_server_(\d{4})_(\d+h\d+)$', "Windows Server", lambda m: f"{m.group(1)} {m.group(2).upper()}", "os"),
    (r'^windows_server_(\d{4})$', "Windows Server", lambda m: m.group(1), "os"),
    (r'^windows_server$', "Windows Server", lambda m: "unknown", "os"),
    (r'^windows_11_(\d+h\d+)$', "Windows 11", lambda m: m.group(1).upper(), "os"),
    (r'^windows_11$', "Windows 11", lambda m: "unknown", "os"),
    (r'^windows_10_(\d{4})$', "Windows 10", lambda m: m.group(1), "os"),
    (r'^windows_10$', "Windows 10", lambda m: "unknown", "os"),
    (r'^windows_8\.1$', "Windows 8.1", lambda m: "unknown", "os"),
    (r'^windows_(7|8|vista|xp)$', lambda m: f"Windows {m.group(1).title()}", lambda m: "unknown", "os"),
    (r'^windows$', "Windows", lambda m: "unknown", "os"),
    (r'^diskstation_manager$', "DSM", lambda m: "unknown", "os"),
    (r'^dsm$', "DSM", lambda m: "unknown", "os"),
    (r'^forti(os|gate|manager|analyzer)$', lambda m: f"Forti{m.group(1).title()}", lambda m: "unknown", "firmware"),
    (r'^ios(_xe|_xr)?$', lambda m: f"Cisco IOS{' X' + m.group(1).upper() if m.group(1) else ''}", lambda m: "unknown", "firmware"),
    (r'^nx-os$', "Cisco NX-OS", lambda m: "unknown", "firmware"),
    (r'^(ubuntu|debian)_linux$', lambda m: m.group(1).title(), lambda m: "unknown", "os"),
    (r'^(linux_kernel|fedora|centos|opensuse|enterprise_linux)$', lambda m: m.group(1).replace("_"," ").title(), lambda m: "unknown", "os"),
    (r'^esxi$', "VMware ESXi", lambda m: "unknown", "firmware"),
    (r'^vcenter_server$', "vCenter Server", lambda m: "unknown", "os"),
    (r'^(macos|mac_os_x|iphone_os)$', lambda m: {"macos":"macOS","mac_os_x":"Mac OS X","iphone_os":"iOS"}[m.group(1)], lambda m: "unknown", "os"),
    (r'^android$', "Android", lambda m: "unknown", "os"),
    (r'^(.+)_firmware$', lambda m: m.group(1).replace("_"," ").title() + " Firmware", lambda m: "unknown", "firmware"),
]

COMPILED_RULES = [(re.compile(p, re.IGNORECASE), n, v, t) for p, n, v, t in NORMALIZATION_RULES]

def normalize_product(vendor, product):
    for pattern, os_nom_def, version_fn, type_produit in COMPILED_RULES:
        if match := pattern.match(product):
            os_nom = os_nom_def(match) if callable(os_nom_def) else os_nom_def
            version = version_fn(match) if callable(version_fn) else version_fn
            # Remplacer NULL par "unknown"
            version = version if version is not None else "unknown"
            return {
                "os_nom": os_nom.strip(),
                "version": version,
                "nvd_vendor": vendor.lower(),
                "nvd_product": product.lower(),
                "type_produit": type_produit
            }
    return None

def extract_os_versions(logger, dry_run=False, verbose=False, vendor_filter=None):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SHOW TABLES LIKE 'os_versions'")
        if not cur.fetchone():
            logger.error("Table os_versions n'existe pas !")
            return False

        vendor_filter_sql = "AND fabricant = %s" if vendor_filter else ""
        query_params = [vendor_filter] if vendor_filter else []

        cur.execute(f"""
            SELECT DISTINCT fabricant, produit
            FROM cve
            WHERE fabricant IS NOT NULL
              AND produit IS NOT NULL
              {vendor_filter_sql}
            ORDER BY fabricant, produit
        """, query_params)

        pairs = cur.fetchall()
        logger.log(f"Couples (fabricant, produit) distincts : {len(pairs)}")

        inserted = 0
        skipped = 0
        no_match = 0
        errors = 0

        # Étape de nettoyage : normaliser les NULL existants
        cur.execute("UPDATE os_versions SET version = 'unknown' WHERE version IS NULL")
        conn.commit()
        logger.log(f"Nettoyage NULL effectué : {cur.rowcount} lignes mises à jour")

        with ProgressBar(len(pairs), "Extracting OS versions") as pbar:
            for i, row in enumerate(pairs, 1):
                vendor = row["fabricant"]
                product = row["produit"]
                entry = normalize_product(vendor, product)

                if entry is None:
                    no_match += 1
                    if verbose:
                        logger.log(f"  [NO MATCH] {vendor} / {product}")
                    pbar.update(i)
                    continue

                if not dry_run:
                    try:
                        cur.execute("""
                            INSERT IGNORE INTO os_versions
                                (os_nom, version, nvd_vendor, nvd_product, type_produit)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (
                            entry["os_nom"],
                            entry["version"],   # jamais NULL (garanti par normalize_product)
                            entry["nvd_vendor"],
                            entry["nvd_product"],
                            entry["type_produit"],
                        ))
                        if cur.rowcount == 1:
                            inserted += 1
                            conn.commit()
                        else:
                            skipped += 1
                    except Exception as e:
                        logger.error(f"Erreur SQL : {e}")
                        errors += 1
                        conn.rollback()
                pbar.update(i)

        logger.success(f"Résultats: {inserted} insérés, {skipped} ignorés, {no_match} non normalisés, {errors} erreurs")
        return True

    except Exception as e:
        logger.error(f"Erreur fatale : {e}")
        return False
    finally:
        conn.close()

# =============================================================================
# MAIN
# =============================================================================

def print_header():
    print("\n" + "="*70)
    print("  🔄 AIR GAPPED CVE — FULL SYNC PIPELINE")
    print("="*70)
    print(f"  Start: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  NVD API Key: {'✓' if NVD_API_KEY else '✗ (slower)'}")
    print(f"  Data dir: {BASE_DIR}/")
    print("="*70 + "\n")

def print_summary(results, total_time):
    print("\n" + "="*70)
    print("  📊 EXECUTION SUMMARY")
    print("="*70)
    mins, secs = divmod(int(total_time.total_seconds()), 60)
    for name, res in results.items():
        status = "✓ SUCCESS" if res["success"] else "✗ FAILED"
        print(f"  {name:25s} {status:12s} ({res.get('duration','N/A')})")
    print("-"*70)
    print(f"  Total time: {mins}m{secs:02d}s")
    print("="*70 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Full sync pipeline: Download → Vendors → CVE → OS Versions")
    parser.add_argument("--raw-dir", default=str(RAW_DIR), help="NVD JSON directory")
    parser.add_argument("--batch-size", type=int, default=500, help="Database batch size")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--dry-run", action="store_true", help="No database writes")
    parser.add_argument("--skip-download", action="store_true", help="Skip download")
    parser.add_argument("--skip-vendors", action="store_true", help="Skip vendors import")
    parser.add_argument("--skip-cve", action="store_true", help="Skip CVE sync")
    parser.add_argument("--skip-os", action="store_true", help="Skip OS extraction")
    args = parser.parse_args()

    print_header()
    start_time = datetime.now(timezone.utc)
    results = {}
    ensure_dirs()

    # STEP 1: Download
    if not args.skip_download:
        logger = StepLogger("STEP 1: Download")
        step_start = datetime.now(timezone.utc)
        try:
            state = load_state()
            last_sync = state.get("last_cve_sync")
            cve_ok = download_cve_incremental(last_sync, logger) if last_sync else download_cve_full(logger)
            cwe_ok = download_cwe(logger)
            success = cve_ok and cwe_ok
        except Exception as e:
            logger.error(f"Failed: {e}")
            success = False
        results["Download NVD"] = {"success": success, "duration": str(datetime.now(timezone.utc)-step_start).split(".")[0]}
        if not success and not args.skip_vendors and not args.skip_cve and not args.skip_os:
            print_summary(results, datetime.now(timezone.utc)-start_time)
            return 1

    # STEP 2: Vendors
    if not args.skip_vendors:
        logger = StepLogger("STEP 2: Vendors")
        step_start = datetime.now(timezone.utc)
        try:
            success = import_vendors_models(args.raw_dir, logger, args.batch_size)
        except Exception as e:
            logger.error(f"Failed: {e}")
            success = False
        results["Import Vendors"] = {"success": success, "duration": str(datetime.now(timezone.utc)-step_start).split(".")[0]}
        if not success and not args.skip_cve and not args.skip_os:
            print_summary(results, datetime.now(timezone.utc)-start_time)
            return 1

    # STEP 3: CVE Sync
    if not args.skip_cve:
        logger = StepLogger("STEP 3: CVE Sync")
        step_start = datetime.now(timezone.utc)
        try:
            success = cve_sync(args.raw_dir, logger)
        except Exception as e:
            logger.error(f"Failed: {e}")
            success = False
        results["Sync CVE"] = {"success": success, "duration": str(datetime.now(timezone.utc)-step_start).split(".")[0]}
        if not success and not args.skip_os:
            print_summary(results, datetime.now(timezone.utc)-start_time)
            return 1

    # STEP 4: OS Versions
    if not args.skip_os:
        logger = StepLogger("STEP 4: OS Versions")
        step_start = datetime.now(timezone.utc)
        try:
            success = extract_os_versions(logger, args.dry_run, args.verbose)
        except Exception as e:
            logger.error(f"Failed: {e}")
            success = False
        results["Extract OS"] = {"success": success, "duration": str(datetime.now(timezone.utc)-step_start).split(".")[0]}

    print_summary(results, datetime.now(timezone.utc)-start_time)
    return 0 if all(r["success"] for r in results.values()) else 1

if __name__ == "__main__":
    sys.exit(main())