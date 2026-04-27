#!/usr/bin/env python3
"""
correlate_and_analyze.py

Pipeline complet :
  1. Corrélation grossière par fabricant (nvd_vendor)
  2. Analyse Mistral pour chaque corrélation nouvelle
  3. Génération de 2 rapports PDF (synthèse + complet)

Usage:
  python correlate_and_analyze.py --help
  python correlate_and_analyze.py correlate
  python correlate_and_analyze.py analyze
  python correlate_and_analyze.py report --output-dir /opt/asset-manager/documents
  python correlate_and_analyze.py run-all
"""

import os
import sys
import json
import logging
import time
from datetime import datetime
from typing import Optional
from tqdm import tqdm

from dotenv import load_dotenv
load_dotenv()

import typer
import pymysql
from mistralai import Mistral
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

sys.path.insert(0, "/opt/asset-manager")
from database import get_connection

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MISTRAL_API_KEY   = os.getenv("MISTRAL_API_KEY", "")
MISTRAL_MODEL     = os.getenv("MISTRAL_MODEL", "mistral-large-latest")

# Pause entre chaque appel Mistral pour éviter le rate limiting (secondes)
MISTRAL_DELAY     = float(os.getenv("MISTRAL_DELAY", "1.5"))

# Nombre max de corrélations à analyser par run (0 = illimité)
MISTRAL_BATCH_MAX = int(os.getenv("MISTRAL_BATCH_MAX", "0"))

logging.basicConfig(
    level=logging.WARNING,  # Seulement les erreurs et warnings
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# Forcer le flush de stdout pour affichage en temps réel
import functools
print = functools.partial(print, flush=True)

app = typer.Typer(help="Pipeline corrélation CVE / analyse Mistral / rapport PDF")

# ---------------------------------------------------------------------------
# Helpers BDD
# ---------------------------------------------------------------------------

def dict_cursor(conn):
    """Retourne un curseur qui renvoie des dicts avec pymysql."""
    return conn.cursor(pymysql.cursors.DictCursor)


# ---------------------------------------------------------------------------
# Comparaison de versions
# ---------------------------------------------------------------------------

def normalize_version(version_str):
    """
    Normalise une version en liste de nombres.
    Ex: "5.4.0-1234" -> [5, 4, 0, 1234]
    """
    if not version_str or version_str == "*":
        return []

    # Nettoyer et extraire les nombres
    import re
    parts = re.findall(r'\d+', str(version_str))
    return [int(p) for p in parts]


def compare_versions(v1, v2):
    """
    Compare deux versions.
    Retourne: -1 si v1 < v2, 0 si égales, 1 si v1 > v2
    """
    v1_parts = normalize_version(v1)
    v2_parts = normalize_version(v2)

    # Comparer composant par composant
    for i in range(max(len(v1_parts), len(v2_parts))):
        part1 = v1_parts[i] if i < len(v1_parts) else 0
        part2 = v2_parts[i] if i < len(v2_parts) else 0

        if part1 < part2:
            return -1
        elif part1 > part2:
            return 1

    return 0


def is_version_affected(asset_version, cve_version_ranges):
    """
    Vérifie si une version d'asset est affectée par une CVE.

    Args:
        asset_version: Version de l'asset (firmware ou OS)
        cve_version_ranges: Liste des ranges de versions de la CVE

    Returns:
        bool: True si la version est affectée
    """
    if not asset_version or asset_version == "*":
        # Pas de version connue -> on considère affecté (prudent)
        return True

    if not cve_version_ranges:
        # Pas de range spécifié -> affecté (tout le produit)
        return True

    for v_range in cve_version_ranges:
        # Version exacte
        if v_range.get("version_exact") and v_range["version_exact"] != "*":
            if compare_versions(asset_version, v_range["version_exact"]) == 0:
                return True
            continue

        # Vérifier les ranges
        in_range = True

        # version_start_including
        if v_range.get("version_start_including"):
            if compare_versions(asset_version, v_range["version_start_including"]) < 0:
                in_range = False

        # version_start_excluding
        if v_range.get("version_start_excluding"):
            if compare_versions(asset_version, v_range["version_start_excluding"]) <= 0:
                in_range = False

        # version_end_including
        if v_range.get("version_end_including"):
            if compare_versions(asset_version, v_range["version_end_including"]) > 0:
                in_range = False

        # version_end_excluding
        if v_range.get("version_end_excluding"):
            if compare_versions(asset_version, v_range["version_end_excluding"]) >= 0:
                in_range = False

        if in_range:
            return True

    return False


def is_os_firmware_cve(cve_product, cve_versions):
    """
    Détermine si une CVE concerne un OS/firmware ou un composant.

    Critères pour OS/firmware:
    - Produit contient: os, firmware, bios, kernel, system
    - Ou pas de produit spécifique (juste le vendor)

    Returns:
        bool: True si c'est une CVE OS/firmware
    """
    if not cve_product:
        return True  # Pas de produit = CVE sur le vendor entier

    product_lower = cve_product.lower()

    # Mots-clés OS/firmware
    os_keywords = ['os', 'firmware', 'bios', 'uefi', 'kernel', 'system',
                   'operating', 'bootloader', 'hypervisor']

    # Mots-clés composants (à exclure)
    component_keywords = ['library', 'lib', 'component', 'plugin', 'module',
                         'service', 'daemon', 'application', 'app', 'tool',
                         'utility', 'driver']

    # Vérifier les mots-clés composants d'abord (exclusion)
    for keyword in component_keywords:
        if keyword in product_lower:
            return False

    # Vérifier les mots-clés OS/firmware
    for keyword in os_keywords:
        if keyword in product_lower:
            return True

    # Si le produit = vendor, c'est généralement l'OS/firmware
    # Ex: "cisco" pour Cisco IOS
    return True

# ---------------------------------------------------------------------------
# Barre de chargement
# ---------------------------------------------------------------------------
def get_progress_bar(iterable, total, description=""):
    """
    Retourne une barre de progression compatible terminal et navigateur.
    Détecte automatiquement l'environnement.
    """
    return tqdm(
        iterable,
        total=total,
        desc=description,
        unit="item",
        ncols=80,                    # largeur fixe, compatible navigateur
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        file=sys.stdout,
        dynamic_ncols=False,         # largeur fixe pour éviter les glitches navigateur
        ascii=False,                 # caractères Unicode pour un rendu propre
    )

# ---------------------------------------------------------------------------
# ÉTAPE 1 — Corrélation grossière par fabricant
# ---------------------------------------------------------------------------

@app.command()
def correlate(
    dry_run: bool = typer.Option(False, "--dry-run", help="Affiche sans insérer")
):
    """
    Corrélation grossière : asset.vendor (nvd_vendor) → cve.fabricant.
    Insère dans correlations uniquement les paires absentes.
    """
    print("\n" + "=" * 70)
    print("  CORRÉLATION CVE / ASSETS")
    print("=" * 70 + "\n")

    conn = get_connection()
    cur  = dict_cursor(conn)

    # Récupère tous les assets actifs avec leur nvd_vendor
    cur.execute("""
        SELECT
            a.id                  AS asset_id,
            a.nom_interne,
            a.type_equipement,
            a.systeme_exploitation,
            a.version_os,
            a.version_firmware,
            a.version_bios,
            a.niveau_criticite,
            a.statut_operationnel,
            pv.nvd_vendor,
            pm.nvd_product,
            pm.nom                AS model_nom,
            s.nom                 AS site_nom,
            c.nom                 AS client_nom
        FROM assets a
        JOIN product_vendors pv ON pv.id = a.vendor_id
        LEFT JOIN product_models pm ON pm.id = a.model_id
        JOIN sites s  ON s.id  = a.site_id
        JOIN clients c ON c.id = s.client_id
        WHERE a.statut_operationnel NOT IN ('hors_service', 'inactif')
          AND a.vendor_id IS NOT NULL
    """)
    assets = cur.fetchall()

    if not assets:
        print("⚠️  Aucun asset actif trouvé.\n")
        conn.close()
        raise typer.Exit()

    inserted = 0
    skipped  = 0
    total_filtered = 0

    if dry_run:
        print("⚠️  Mode DRY-RUN : aucune insertion en base\n")

    print(f"Assets à analyser : {len(assets)}")
    print("Filtres activés : OS/firmware only + comparaison de versions\n")

    with tqdm(
        assets,
        total=len(assets),
        desc="Corrélation CVE",
        unit="asset",
        ncols=100,
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
        file=sys.stdout,
        dynamic_ncols=False,
        ascii=False,
    ) as pbar:
        for asset in pbar:
            nvd_vendor = asset["nvd_vendor"]
            asset_name = asset['nom_interne'][:25]

            # Récupère toutes les CVE pour ce fabricant
            cur.execute("""
                SELECT cve_id, cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
                       fabricant, produit, description, versions_affectees
                FROM cve
                WHERE fabricant = %s
            """, (nvd_vendor,))
            cves = cur.fetchall()

            asset_new = 0
            filtered_out = 0

            for cve in cves:
                # === FILTRE 1 : Type de CVE (OS/firmware uniquement) ===
                try:
                    versions_data = json.loads(cve["versions_affectees"]) if cve["versions_affectees"] else []
                except:
                    versions_data = []

                if not is_os_firmware_cve(cve["produit"], versions_data):
                    filtered_out += 1
                    continue

                # === FILTRE 2 : Comparaison de versions ===
                # Déterminer quelle version utiliser selon le type de CVE
                cve_product_lower = (cve["produit"] or "").lower()

                # Si la CVE concerne le BIOS
                if "bios" in cve_product_lower or "uefi" in cve_product_lower:
                    asset_version = asset["version_bios"]
                else:
                    # Sinon, vérifier firmware OU OS
                    asset_version = asset["version_firmware"] or asset["version_os"]

                if asset_version:
                    if not is_version_affected(asset_version, versions_data):
                        # Version de l'asset est supérieure -> pas affecté
                        filtered_out += 1
                        continue

                # === FILTRE 3 : Doublon ===
                cur.execute("""
                    SELECT id FROM correlations
                    WHERE asset_id = %s AND cve_id = %s
                """, (asset["asset_id"], cve["cve_id"]))

                if cur.fetchone():
                    skipped += 1
                    continue

                # === Calcul du type_correlation ===
                # Affirme si version connue ET versions_data non vide ET version affectée
                if asset_version and versions_data and is_version_affected(asset_version, versions_data):
                    type_corr = 'affirme'
                else:
                    type_corr = 'informatif'

                # === Insertion ===
                if not dry_run:
                    cur.execute("""
                        INSERT INTO correlations
                            (asset_id, cve_id, statut, type_correlation, date_detection)
                        VALUES
                            (%s, %s, 'nouveau', %s, NOW())
                    """, (asset["asset_id"], cve["cve_id"], type_corr))

                inserted += 1
                asset_new += 1

            # Commit par asset pour ne pas tout perdre en cas d'erreur
            if not dry_run:
                conn.commit()

            total_filtered += filtered_out

            # Mise à jour de la barre
            pbar.set_postfix_str(f"{asset_name} | +{asset_new} CVE | Filtrées: {filtered_out}")

    conn.close()

    print(f"\n{'='*70}")
    print(f"  ✅ Nouvelles corrélations : {inserted}")
    print(f"  ⏭️  Doublons ignorés       : {skipped}")
    print(f"  🔍 CVE filtrées (hors périmètre) : {total_filtered}")
    print(f"     → Composants/librairies exclus")
    print(f"     → Versions non affectées")
    print(f"{'='*70}\n")


# ---------------------------------------------------------------------------
# ÉTAPE 2 — Analyse Mistral
# ---------------------------------------------------------------------------

MISTRAL_SYSTEM_PROMPT = """
Tu es un expert en PATCH MANAGEMENT pour des systèmes d'exploitation et firmware.

MISSION EXCLUSIVE : Déterminer si un patch/mise à jour OS/firmware doit être appliqué.

CONTEXTE CRITIQUE :
- Environnements air-gapped (isolés d'Internet)
- Focus UNIQUEMENT sur les mises à jour OS et firmware patchables
- Ne PAS analyser les composants/librairies internes hypothétiques
- Ne PAS faire de suppositions sur des composants non mentionnés explicitement

CRITÈRES D'ANALYSE :
1. La CVE affecte-t-elle DIRECTEMENT l'OS ou le firmware de l'équipement ?
2. La version actuelle est-elle dans le range des versions vulnérables ?
3. Un patch officiel du fabricant est-il nécessaire ?
4. Le vecteur d'attaque est-il réaliste en air-gap ?

SI LA CVE CONCERNE :
- ✅ Un composant OS/firmware patchable → asset_concerne = true
- ❌ Un composant hypothétique non vérifié → asset_concerne = false
- ❌ Une librairie/service non mentionné → asset_concerne = false

Tu réponds UNIQUEMENT en JSON valide, sans markdown, sans texte avant ou après.
"""

MISTRAL_USER_PROMPT = """
ÉQUIPEMENT À PATCHER :
- Nom : {nom_interne}
- Type : {type_equipement}
- Fabricant : {nvd_vendor}
- Modèle : {model_nom}
- OS actuel : {systeme_exploitation}
- Version OS actuelle : {version_os}
- Version firmware actuelle : {version_firmware}
- Version BIOS actuelle : {version_bios}
- Criticité opérationnelle : {niveau_criticite}

CVE CANDIDATE POUR PATCH :
- ID : {cve_id}
- Description : {description}
- Score CVSS v3 : {cvss_v3_score}
- Sévérité : {cvss_v3_severity}
- Vecteur : {cvss_v3_vector}
- Produit NVD : {produit}
- Versions vulnérables : {versions_affectees}

QUESTIONS CRITIQUES :
1. Cette CVE affecte-t-elle l'OS/firmware/BIOS DIRECTEMENT (pas un composant hypothétique) ?
2. La version actuelle ({version_os} / {version_firmware} / {version_bios}) est-elle vulnérable ?
3. Un patch du fabricant {nvd_vendor} est-il nécessaire ?
4. Le risque est-il réel en environnement air-gapped ?

Réponds avec ce JSON exact :
{{
  "asset_concerne": true|false,
  "confirmation_version": true|false,
  "confidence": "haute"|"moyenne"|"faible",
  "raison_inclusion_exclusion": "Explication PATCH MANAGEMENT : OS/firmware affecté ou pas",
  "exploitable_air_gap": true|false|null,
  "explication_air_gap": "Vecteur d'attaque en air-gap",
  "score_contextuel": 0.0,
  "priorite": "critique"|"haute"|"moyenne"|"basse",
  "analyse_complete": "Focus sur la nécessité de PATCHER (2-3 phrases)",
  "risque_reel": "Impact réel si le patch n'est PAS appliqué",
  "recommandation": "PATCH à appliquer (version cible du fabricant) ou IGNORER si faux positif"
}}

RÈGLES SCORE CONTEXTUEL (0.0-10.0) :
- Pars du CVSS v3 de base
- -3.0 si vecteur réseau (AV:N) car air-gap
- -5.0 si asset_concerne = false (pas un vrai patch OS/firmware)
- +1.0 si criticité asset = critique/élevée
- Minimum 0.0, maximum 10.0

RÈGLES PRIORITÉ :
- score >= 9.0 → critique (patch urgent)
- score >= 7.0 → haute (patch prioritaire)
- score >= 4.0 → moyenne (patch planifié)
- score < 4.0 → basse (surveiller)

RÈGLES CONFIRMATION_VERSION :
- confirmation_version = true si la version actuelle de l'asset est explicitement dans le range des versions vulnérables de la CVE
- confirmation_version = false sinon (version inconnue, range absent, ou version non affectée)

IMPORTANT : Si la CVE ne nécessite PAS de patch OS/firmware patchable → asset_concerne = false
"""


def analyze_with_mistral(client: Mistral, correlation: dict) -> Optional[dict]:
    """
    Envoie une corrélation à Mistral et retourne le JSON parsé.
    Retourne None en cas d'échec.
    """
    prompt = MISTRAL_USER_PROMPT.format(
        nom_interne          = correlation["nom_interne"]          or "N/A",
        type_equipement      = correlation["type_equipement"]      or "N/A",
        nvd_vendor           = correlation["nvd_vendor"]           or "N/A",
        model_nom            = correlation["model_nom"]            or "N/A",
        systeme_exploitation = correlation["systeme_exploitation"] or "N/A",
        version_os           = correlation["version_os"]           or "N/A",
        version_firmware     = correlation["version_firmware"]     or "N/A",
        version_bios         = correlation["version_bios"]         or "N/A",
        niveau_criticite     = correlation["niveau_criticite"]     or "N/A",
        site_nom             = correlation["site_nom"]             or "N/A",
        client_nom           = correlation["client_nom"]           or "N/A",
        cve_id               = correlation["cve_id"],
        description          = (correlation["description"] or "")[:800],
        cvss_v3_score        = correlation["cvss_v3_score"]        or "N/A",
        cvss_v3_severity     = correlation["cvss_v3_severity"]     or "N/A",
        cvss_v3_vector       = correlation["cvss_v3_vector"]       or "N/A",
        fabricant            = correlation["fabricant"]            or "N/A",
        produit              = correlation["produit"]              or "N/A",
        versions_affectees   = json.dumps(
            correlation["versions_affectees"] or [], ensure_ascii=False
        )[:600],
    )

    try:
        response = client.chat.complete(
            model    = MISTRAL_MODEL,
            messages = [
                {"role": "system", "content": MISTRAL_SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            temperature = 0.1,
            max_tokens  = 1024,
        )
        raw = response.choices[0].message.content.strip()

        # Nettoyage défensif si Mistral ajoute du markdown malgré la consigne
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        result = json.loads(raw)
        return result

    except json.JSONDecodeError as e:
        log.error(f"JSON invalide pour {correlation['cve_id']} : {e}")
        return None
    except Exception as e:
        log.error(f"Erreur Mistral pour {correlation['cve_id']} : {type(e).__name__}: {e}")
        return None


@app.command()
def analyze(
    batch_max: int = typer.Option(
        MISTRAL_BATCH_MAX, "--batch-max",
        help="Nombre max de corrélations à traiter (0 = toutes)"
    ),
    asset_id: Optional[int] = typer.Option(
        None, "--asset-id",
        help="Restreindre l'analyse à un asset spécifique"
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Ré-analyser aussi les corrélations déjà analysées"
    ),
):
    """
    Envoie chaque corrélation 'nouveau' à Mistral pour analyse.
    Met à jour correlations avec le résultat.
    """
    print("\n" + "=" * 70)
    print("  ANALYSE MISTRAL AI")
    print("=" * 70 + "\n")

    if not MISTRAL_API_KEY:
        print("❌ MISTRAL_API_KEY non définie dans l'environnement\n")
        raise typer.Exit(1)

    mistral_client = Mistral(api_key=MISTRAL_API_KEY)
    conn = get_connection()
    cur  = dict_cursor(conn)

    # Statuts éligibles et filtrage par date_analyse pour éviter les réanalyses
    if not force:
        statuts = "('nouveau')"
        date_filter = "AND co.date_analyse IS NULL"
        print("Mode : Analyse uniquement des nouvelles CVE (cache activé)")
    else:
        statuts = "('nouveau','en_analyse','confirme','faux_positif')"
        date_filter = ""
        print("⚠️  Mode FORCE : Réanalyse TOUT (coût API élevé!)")

    asset_filter = f"AND co.asset_id = {asset_id}" if asset_id else ""
    limit_clause = f"LIMIT {batch_max}" if batch_max > 0 else ""

    cur.execute(f"""
        SELECT
            co.id                 AS correlation_id,
            co.asset_id,
            co.cve_id,
            a.nom_interne,
            a.type_equipement,
            a.systeme_exploitation,
            a.version_os,
            a.version_firmware,
            a.version_bios,
            a.niveau_criticite,
            pv.nvd_vendor,
            pm.nom                AS model_nom,
            s.nom                 AS site_nom,
            cl.nom                AS client_nom,
            cv.description,
            cv.cvss_v3_score,
            cv.cvss_v3_severity,
            cv.cvss_v3_vector,
            cv.fabricant,
            cv.produit,
            cv.versions_affectees
        FROM correlations co
        JOIN assets a  ON a.id  = co.asset_id
        JOIN cve cv    ON cv.cve_id = co.cve_id
        JOIN product_vendors pv ON pv.id = a.vendor_id
        LEFT JOIN product_models pm ON pm.id = a.model_id
        JOIN sites s   ON s.id  = a.site_id
        JOIN clients cl ON cl.id = s.client_id
        WHERE co.statut IN {statuts}
        {date_filter}
        {asset_filter}
        ORDER BY cv.cvss_v3_score DESC
        {limit_clause}
    """)
    correlations = cur.fetchall()

    if not correlations:
        print("✅ Aucune nouvelle corrélation à analyser\n")
        conn.close()
        return

    processed = 0
    errors    = 0
    confirmed = 0
    false_positives = 0

    if batch_max > 0:
        print(f"Limite batch : {batch_max} corrélations")
    print(f"Corrélations à analyser : {len(correlations)}\n")

    with tqdm(
        correlations,
        total=len(correlations),
        desc="Analyse IA",
        unit="CVE",
        ncols=100,
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
        file=sys.stdout,
        dynamic_ncols=False,
        ascii=False,
    ) as pbar:
        for corr in pbar:
            # Afficher les stats dans la barre de progression
            asset_name = corr['nom_interne'][:20]
            pbar.set_postfix_str(f"{asset_name} | ✅ {confirmed} | ❌ {false_positives} | ⚠️ {errors}")

            # Passe en 'en_analyse' pendant le traitement
            cur.execute("""
                UPDATE correlations SET statut = 'en_analyse'
                WHERE id = %s
            """, (corr["correlation_id"],))
            conn.commit()

            # Désérialise versions_affectees si c'est une string
            if isinstance(corr["versions_affectees"], str):
                try:
                    corr["versions_affectees"] = json.loads(corr["versions_affectees"])
                except Exception:
                    corr["versions_affectees"] = []

            # Analyse via Mistral
            result = analyze_with_mistral(mistral_client, corr)

            if result is None:
                errors += 1
                # Repasse en 'nouveau' pour retry ultérieur
                cur.execute("""
                    UPDATE correlations SET statut = 'nouveau'
                    WHERE id = %s
                """, (corr["correlation_id"],))
                conn.commit()
                continue

            # Détermine le statut final
            if not result.get("asset_concerne", True):
                statut_final = "faux_positif"
                false_positives += 1
            else:
                statut_final = "confirme"
                confirmed += 1

            score = result.get("score_contextuel", None)
            if isinstance(score, (int, float)):
                score = max(0.0, min(10.0, float(score)))

            analyse_text = (
                f"[Confidence: {result.get('confidence','N/A')}]\n\n"
                f"{result.get('analyse_complete','')}\n\n"
                f"Recommandation: {result.get('recommandation','')}"
            )

            # Mise à jour en base
            cur.execute("""
                UPDATE correlations SET
                    statut              = %s,
                    priorite            = %s,
                    exploitable_air_gap = %s,
                    analyse_mistral     = %s,
                    risque_reel         = %s,
                    score_contextuel    = %s,
                    date_analyse        = NOW()
                WHERE id = %s
            """, (
                statut_final,
                result.get("priorite"),
                result.get("exploitable_air_gap"),
                analyse_text,
                result.get("risque_reel"),
                score,
                corr["correlation_id"],
            ))

            # Mise à jour de type_correlation basée sur l'analyse Mistral
            if statut_final == 'confirme' and result.get("confirmation_version") is True:
                cur.execute("""
                    UPDATE correlations SET type_correlation = 'affirme'
                    WHERE id = %s
                """, (corr["correlation_id"],))
            elif statut_final == 'faux_positif':
                cur.execute("""
                    UPDATE correlations SET type_correlation = 'informatif'
                    WHERE id = %s
                """, (corr["correlation_id"],))
            # Sinon, ne pas toucher type_correlation (garde la valeur initiale de correlate())

            conn.commit()

            processed += 1
            time.sleep(MISTRAL_DELAY)

    conn.close()

    print(f"\n{'='*70}")
    print(f"  ✅ Confirmées      : {confirmed}")
    print(f"  ❌ Faux positifs   : {false_positives}")
    print(f"  ⚠️  Erreurs        : {errors}")
    print(f"{'='*70}\n")


# ---------------------------------------------------------------------------
# ÉTAPE 3 — Rapport PDF
# ---------------------------------------------------------------------------

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
        "title": ParagraphStyle(
            "title", parent=styles["Title"],
            fontSize=22, spaceAfter=6, textColor=colors.HexColor("#1A252F")
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=styles["Normal"],
            fontSize=11, textColor=colors.HexColor("#5D6D7E"), spaceAfter=20
        ),
        "h1": ParagraphStyle(
            "h1", parent=styles["Heading1"],
            fontSize=16, textColor=colors.HexColor("#1A252F"),
            spaceBefore=20, spaceAfter=8,
            borderPad=4,
        ),
        "h2": ParagraphStyle(
            "h2", parent=styles["Heading2"],
            fontSize=13, textColor=colors.HexColor("#2C3E50"),
            spaceBefore=14, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "h3", parent=styles["Heading3"],
            fontSize=11, textColor=colors.HexColor("#34495E"),
            spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", parent=styles["Normal"],
            fontSize=9, leading=13, spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "small", parent=styles["Normal"],
            fontSize=8, leading=11, textColor=colors.HexColor("#5D6D7E"),
        ),
        "badge_critique": ParagraphStyle(
            "badge_critique", parent=styles["Normal"],
            fontSize=9, textColor=colors.white, alignment=TA_CENTER,
        ),
    }
    return {**{k: styles[k] for k in styles.byName}, **custom}


def priority_badge(priorite: Optional[str], styles: dict) -> Paragraph:
    color = PRIORITY_COLORS.get(priorite, colors.grey)
    label = (priorite or "N/A").upper()
    return Paragraph(
        f'<font color="white"><b>{label}</b></font>',
        ParagraphStyle(
            "badge", parent=styles["Normal"],
            fontSize=8, alignment=TA_CENTER,
            backColor=color, borderPad=3,
        )
    )


def generate_synthese_pdf(synthese_pdf: str, rows: list, stats: dict, styles: dict):
    """
    Génère le PDF de synthèse avec les statistiques globales et la liste des
    vulnérabilités critiques et hautes par asset.
    """
    log.info(f"Génération du PDF de synthèse: {synthese_pdf}")

    doc = SimpleDocTemplate(
        synthese_pdf,
        pagesize=A4,
        leftMargin=2*cm,
        rightMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )
    story = []

    # Page de titre
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("Synthèse des Vulnérabilités", styles["title"]))
    story.append(Paragraph(
        f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} — "
        f"Environnements air-gapped",
        styles["subtitle"]
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1A252F")))
    story.append(Spacer(1, 0.5*cm))

    # Tableau de synthèse globale
    story.append(Paragraph("Synthèse globale", styles["h1"]))
    summary_data = [
        ["Indicateur", "Valeur"],
        ["Total vulnérabilités analysées", str(stats["total"] or 0)],
        ["Critique",  str(stats["nb_critique"] or 0)],
        ["Haute",     str(stats["nb_haute"]    or 0)],
        ["Moyenne",   str(stats["nb_moyenne"]  or 0)],
        ["Basse",     str(stats["nb_basse"]    or 0)],
        ["Exploitables en air-gap", str(stats["nb_air_gap"] or 0)],
    ]
    summary_table = Table(summary_data, colWidths=[10*cm, 4*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#1A252F")),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#F2F3F4"), colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#BDC3C7")),
        ("ALIGN",       (1, 0), (1, -1),  "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0,0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.8*cm))

    # Liste synthétique des vulnérabilités critiques et hautes
    story.append(Paragraph("Vulnérabilités critiques et hautes par asset", styles["h1"]))
    story.append(Spacer(1, 0.3*cm))

    # Filtrer pour ne garder que critiques et hautes
    critical_high_rows = [r for r in rows if r["priorite"] in ("critique", "haute")]

    if critical_high_rows:
        # Regrouper par asset
        from itertools import groupby
        from operator import itemgetter

        # Trier par client, site, asset, puis priorité
        sorted_rows = sorted(
            critical_high_rows,
            key=lambda r: (
                r["client_nom"],
                r["site_nom"],
                r["nom_interne"],
                PRIORITY_ORDER.get(r["priorite"], 4)
            )
        )

        # Créer la table des vulnérabilités
        vuln_data = [["CVE ID", "Client", "Site", "Asset", "Priorité", "Score", "Recommandation"]]

        for row in sorted_rows:
            # Extraire une recommandation courte de l'analyse Mistral
            analyse = row.get("analyse_mistral", "")
            recommandation = ""
            if analyse:
                # Chercher la ligne "Recommandation:" dans l'analyse
                lines = analyse.split("\n")
                for line in lines:
                    if line.strip().startswith("Recommandation:"):
                        recommandation = line.replace("Recommandation:", "").strip()
                        break
                if not recommandation:
                    # Si pas trouvé, prendre le risque réel en raccourci
                    recommandation = (row.get("risque_reel", "") or "Voir rapport complet")[:80]
            else:
                recommandation = "Voir rapport complet"

            p_color = PRIORITY_COLORS.get(row["priorite"], colors.grey)

            vuln_data.append([
                Paragraph(f'<b>{row["cve_id"]}</b>', styles["small"]),
                Paragraph(row["client_nom"] or "N/A", styles["small"]),
                Paragraph(row["site_nom"] or "N/A", styles["small"]),
                Paragraph(row["nom_interne"] or "N/A", styles["small"]),
                Paragraph(
                    f'<b>{(row["priorite"] or "N/A").upper()}</b>',
                    ParagraphStyle("priority", parent=styles["small"],
                                 textColor=colors.white, alignment=TA_CENTER)
                ),
                Paragraph(
                    f'<b>{row["score_contextuel"] or "N/A"}</b>',
                    styles["small"]
                ),
                Paragraph(recommandation[:100] + "..." if len(recommandation) > 100 else recommandation,
                         styles["small"]),
            ])

        vuln_table = Table(
            vuln_data,
            colWidths=[2.5*cm, 2.5*cm, 2.5*cm, 3*cm, 2*cm, 1.5*cm, 3*cm]
        )

        # Appliquer les styles de base
        table_style = [
            ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#1A252F")),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#BDC3C7")),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0,0), (-1, -1), 4),
        ]

        # Ajouter les couleurs de fond pour chaque priorité
        for i, row in enumerate(sorted_rows, start=1):
            p_color = PRIORITY_COLORS.get(row["priorite"], colors.grey)
            table_style.append(("BACKGROUND", (4, i), (4, i), p_color))

        vuln_table.setStyle(TableStyle(table_style))
        story.append(vuln_table)
    else:
        story.append(Paragraph("Aucune vulnérabilité critique ou haute trouvée.", styles["body"]))

    # Générer le PDF
    log.info(f"Construction du PDF de synthèse...")
    doc.build(story)
    log.info(f"✓ PDF de synthèse généré: {synthese_pdf}")


def generate_complet_pdf(complet_pdf: str, rows: list, stats: dict, styles: dict):
    """
    Génère le PDF complet avec tous les détails organisés par Client → Site → Asset.
    """
    log.info(f"Génération du PDF complet: {complet_pdf}")

    doc = SimpleDocTemplate(
        complet_pdf,
        pagesize=A4,
        leftMargin=2*cm,
        rightMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )
    story = []

    # Page de titre
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("Rapport Complet de Vulnérabilités", styles["title"]))
    story.append(Paragraph(
        f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} — "
        f"Environnements air-gapped",
        styles["subtitle"]
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1A252F")))
    story.append(Spacer(1, 0.5*cm))

    # Tableau de synthèse globale
    story.append(Paragraph("Synthèse globale", styles["h1"]))
    summary_data = [
        ["Indicateur", "Valeur"],
        ["Total vulnérabilités analysées", str(stats["total"] or 0)],
        ["Critique",  str(stats["nb_critique"] or 0)],
        ["Haute",     str(stats["nb_haute"]    or 0)],
        ["Moyenne",   str(stats["nb_moyenne"]  or 0)],
        ["Basse",     str(stats["nb_basse"]    or 0)],
        ["Exploitables en air-gap", str(stats["nb_air_gap"] or 0)],
    ]
    summary_table = Table(summary_data, colWidths=[10*cm, 4*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#1A252F")),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#F2F3F4"), colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#BDC3C7")),
        ("ALIGN",       (1, 0), (1, -1),  "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0,0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(PageBreak())

    # Regroupement par client → site → asset
    from itertools import groupby
    from operator import itemgetter

    clients_count = 0
    for client_nom, client_rows in groupby(rows, key=itemgetter("client_nom")):
        clients_count += 1
        client_rows = list(client_rows)
        log.debug(f"Traitement du client: {client_nom} ({len(client_rows)} vulnérabilités)")
        story.append(Paragraph(f"Client : {client_nom}", styles["h1"]))
        story.append(HRFlowable(
            width="100%", thickness=1,
            color=colors.HexColor("#2C3E50")
        ))

        for site_nom, site_rows in groupby(client_rows, key=itemgetter("site_nom")):
            site_rows = list(site_rows)
            story.append(Paragraph(f"Site : {site_nom}", styles["h2"]))

            for asset_nom, asset_rows in groupby(site_rows, key=itemgetter("nom_interne")):
                asset_rows = list(asset_rows)
                first      = asset_rows[0]

                story.append(Paragraph(f"Asset : {asset_nom}", styles["h3"]))

                # Fiche asset
                asset_info = [
                    ["Type",        first["type_equipement"] or "N/A",
                     "Fabricant",   first["fabricant_nvd"]   or "N/A"],
                    ["Modèle",      first["model_nom"]        or "N/A",
                     "Criticité",   first["niveau_criticite"] or "N/A"],
                    ["OS",          first["systeme_exploitation"] or "N/A",
                     "Version OS",  first["version_os"]       or "N/A"],
                    ["Firmware",    first["version_firmware"] or "N/A",
                     "BIOS",        first["version_bios"]     or "N/A"],
                ]
                asset_table = Table(asset_info, colWidths=[3*cm, 5.5*cm, 3*cm, 5.5*cm])
                asset_table.setStyle(TableStyle([
                    ("BACKGROUND",  (0, 0), (-1, -1), colors.HexColor("#EBF5FB")),
                    ("FONTNAME",    (0, 0), (0, -1),  "Helvetica-Bold"),
                    ("FONTNAME",    (2, 0), (2, -1),  "Helvetica-Bold"),
                    ("FONTSIZE",    (0, 0), (-1, -1), 8),
                    ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#AED6F1")),
                    ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING",  (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING",(0,0), (-1, -1), 4),
                ]))
                story.append(asset_table)
                story.append(Spacer(1, 0.3*cm))

                # Tri des CVE par priorité
                sorted_cves = sorted(
                    asset_rows,
                    key=lambda r: PRIORITY_ORDER.get(r["priorite"], 4)
                )

                for row in sorted_cves:
                    p_color = PRIORITY_COLORS.get(row["priorite"], colors.grey)

                    # En-tête CVE
                    cve_header_data = [[
                        Paragraph(
                            f'<b>{row["cve_id"]}</b>',
                            ParagraphStyle("ch", parent=styles["Normal"],
                                           fontSize=10, textColor=colors.white)
                        ),
                        Paragraph(
                            f'<b>{(row["priorite"] or "N/A").upper()}</b>',
                            ParagraphStyle("cp", parent=styles["Normal"],
                                           fontSize=9, textColor=colors.white,
                                           alignment=TA_CENTER)
                        ),
                        Paragraph(
                            f'CVSS: <b>{row["cvss_v3_score"] or "N/A"}</b> '
                            f'({row["cvss_v3_severity"] or "N/A"})',
                            ParagraphStyle("cs", parent=styles["Normal"],
                                           fontSize=9, textColor=colors.white,
                                           alignment=TA_CENTER)
                        ),
                        Paragraph(
                            f'Score contextuel: <b>{row["score_contextuel"] or "N/A"}</b>',
                            ParagraphStyle("csc", parent=styles["Normal"],
                                           fontSize=9, textColor=colors.white,
                                           alignment=TA_CENTER)
                        ),
                    ]]
                    cve_header = Table(
                        cve_header_data,
                        colWidths=[5*cm, 3*cm, 4*cm, 5*cm]
                    )
                    cve_header.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), p_color),
                        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                    ]))
                    story.append(cve_header)

                    # Corps CVE
                    air_gap_label = {
                        True:  "⚠ Exploitable en air-gap",
                        False: "✓ Non exploitable en air-gap",
                        None:  "? Indéterminé",
                    }.get(row["exploitable_air_gap"], "? Indéterminé")

                    cve_body_data = [
                        [Paragraph("<b>Description</b>", styles["small"]),
                         Paragraph(
                             (row["cve_description"] or "N/A")[:400],
                             styles["small"]
                         )],
                        [Paragraph("<b>Vecteur CVSS</b>", styles["small"]),
                         Paragraph(row["cvss_v3_vector"] or "N/A", styles["small"])],
                        [Paragraph("<b>Air-gap</b>", styles["small"]),
                         Paragraph(air_gap_label, styles["small"])],
                        [Paragraph("<b>Risque réel</b>", styles["small"]),
                         Paragraph(row["risque_reel"] or "N/A", styles["small"])],
                        [Paragraph("<b>Analyse</b>", styles["small"]),
                         Paragraph(
                             (row["analyse_mistral"] or "N/A").replace("\n", "<br/>"),
                             styles["small"]
                         )],
                    ]
                    cve_body = Table(cve_body_data, colWidths=[3.5*cm, 13.5*cm])
                    cve_body.setStyle(TableStyle([
                        ("BACKGROUND",   (0, 0), (0, -1), colors.HexColor("#F8F9FA")),
                        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE",     (0, 0), (-1,-1), 8),
                        ("GRID",         (0, 0), (-1,-1), 0.3, colors.HexColor("#BDC3C7")),
                        ("VALIGN",       (0, 0), (-1,-1), "TOP"),
                        ("TOPPADDING",   (0, 0), (-1,-1), 4),
                        ("BOTTOMPADDING",(0, 0), (-1,-1), 4),
                    ]))
                    story.append(cve_body)
                    story.append(Spacer(1, 0.4*cm))

                story.append(Spacer(1, 0.5*cm))

        story.append(PageBreak())

    # Générer le PDF
    log.info(f"Génération du fichier PDF complet final ({clients_count} clients traités)...")
    doc.build(story)
    log.info(f"✓ PDF complet généré: {complet_pdf}")


@app.command()
def report(
    output_dir: str          = typer.Option("/opt/asset-manager/documents", "--output-dir", "-d"),
    client_id:  Optional[int] = typer.Option(None,  "--client-id",  help="Filtrer par client"),
    asset_id:   Optional[int] = typer.Option(None,  "--asset-id",   help="Filtrer par asset"),
    statuts:    str           = typer.Option(
        "confirme,mitige",
        "--statuts",
        help="Statuts à inclure, séparés par virgule"
    ),
    min_score:  float         = typer.Option(0.0,   "--min-score",  help="Score contextuel minimum"),
):
    """
    Génère 2 PDFs : une synthèse et un rapport complet des vulnérabilités.
    """
    print("\n" + "=" * 70)
    print("  GÉNÉRATION DES RAPPORTS PDF")
    print("=" * 70 + "\n")

    # Créer le répertoire de sortie s'il n'existe pas
    import os
    os.makedirs(output_dir, exist_ok=True)

    # Générer les noms de fichiers avec timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    synthese_pdf = os.path.join(output_dir, f"synthese_vulnerabilites_{timestamp}.pdf")
    complet_pdf = os.path.join(output_dir, f"rapport_complet_{timestamp}.pdf")

    conn = get_connection()
    cur  = dict_cursor(conn)

    statut_list = [s.strip() for s in statuts.split(",")]
    placeholders = ",".join(["%s"] * len(statut_list))

    filters      = [f"co.statut IN ({placeholders})"]
    params       = statut_list[:]

    if min_score > 0:
        filters.append("co.score_contextuel >= %s")
        params.append(min_score)
    if client_id:
        filters.append("cl.id = %s")
        params.append(client_id)
    if asset_id:
        filters.append("a.id = %s")
        params.append(asset_id)

    where = " AND ".join(filters)

    cur.execute(f"""
        SELECT
            cl.id                 AS client_id,
            cl.nom                AS client_nom,
            s.nom                 AS site_nom,
            a.id                  AS asset_id,
            a.nom_interne,
            a.type_equipement,
            a.systeme_exploitation,
            a.version_os,
            a.version_firmware,
            a.version_bios,
            a.niveau_criticite,
            pv.nvd_vendor         AS fabricant_nvd,
            pm.nom                AS model_nom,
            co.id                 AS correlation_id,
            co.cve_id,
            co.statut,
            co.priorite,
            co.score_contextuel,
            co.exploitable_air_gap,
            co.analyse_mistral,
            co.risque_reel,
            co.date_detection,
            co.date_analyse,
            cv.cvss_v3_score,
            cv.cvss_v3_severity,
            cv.cvss_v3_vector,
            cv.description        AS cve_description
        FROM correlations co
        JOIN assets a   ON a.id  = co.asset_id
        JOIN cve cv     ON cv.cve_id = co.cve_id
        JOIN product_vendors pv ON pv.id = a.vendor_id
        LEFT JOIN product_models pm ON pm.id = a.model_id
        JOIN sites s    ON s.id  = a.site_id
        JOIN clients cl ON cl.id = s.client_id
        WHERE {where}
        ORDER BY cl.nom, s.nom, a.nom_interne,
                 FIELD(co.priorite,'critique','haute','moyenne','basse')
    """, params)

    rows = cur.fetchall()
    print(f"Vulnérabilités trouvées : {len(rows)}")

    # Statistiques globales
    cur.execute(f"""
        SELECT
            COUNT(*) AS total,
            SUM(co.priorite = 'critique') AS nb_critique,
            SUM(co.priorite = 'haute')    AS nb_haute,
            SUM(co.priorite = 'moyenne')  AS nb_moyenne,
            SUM(co.priorite = 'basse')    AS nb_basse,
            SUM(co.exploitable_air_gap = 1) AS nb_air_gap
        FROM correlations co
        JOIN assets a ON a.id = co.asset_id
        JOIN sites s  ON s.id = a.site_id
        JOIN clients cl ON cl.id = s.client_id
        WHERE {where}
    """, params)
    stats = cur.fetchone()
    conn.close()

    if not rows:
        print("⚠️  Aucune vulnérabilité trouvée avec ces filtres\n")
        raise typer.Exit(0)

    # ---- Construction des PDFs ----
    styles = build_pdf_styles()

    # Génération du PDF de synthèse
    print("\n[1/2] Génération PDF synthèse...")
    generate_synthese_pdf(synthese_pdf, rows, stats, styles)
    print("✅ Synthèse générée")

    # Génération du PDF complet
    print("\n[2/2] Génération PDF complet...")
    generate_complet_pdf(complet_pdf, rows, stats, styles)
    print("✅ Rapport complet généré")

    print(f"\n{'='*70}")
    print(f"  📊 Synthèse        : {os.path.basename(synthese_pdf)}")
    print(f"  📋 Rapport complet : {os.path.basename(complet_pdf)}")
    print(f"  📁 Répertoire      : {output_dir}")
    print(f"  📄 Vulnérabilités  : {len(rows)}")
    print(f"{'='*70}\n")


# ---------------------------------------------------------------------------
# Commande tout-en-un
# ---------------------------------------------------------------------------

@app.command("run-all")
def run_all(
    batch_max:  int           = typer.Option(MISTRAL_BATCH_MAX, "--batch-max"),
):
    """Lance corrélation → analyse en une seule commande."""
    print("\n" + "=" * 70)
    print("  PIPELINE COMPLET : CORRÉLATION → ANALYSE")
    print("=" * 70)

    correlate()
    analyze(batch_max=batch_max, asset_id=None, force=False)

    print("=" * 70)
    print("  ✅ PIPELINE TERMINÉ")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Aucun argument fourni : on force l'exécution du pipeline complet
        sys.argv.append("run-all")
    app()
