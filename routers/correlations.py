from typing import Optional, List
from fastapi import APIRouter, HTTPException, Response, Query, BackgroundTasks
import logging
from pathlib import Path
from pydantic import BaseModel
from typing import Optional
import subprocess
import os
from database import get_connection

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent.parent

# ─── Schémas Pydantic ───────────────────────────────────────────────────────

class CorrelationUpdate(BaseModel):
    statut: Optional[str] = None
    priorite: Optional[str] = None
    override_utilisateur: Optional[str] = None
    notes: Optional[str] = None

# ─── Endpoints ──────────────────────────────────────────────────────────────

@router.get("/stats")
def get_correlation_stats():
    """Retourne les statistiques des corrélations par statut et priorité"""
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN statut = 'confirme' THEN 1 ELSE 0 END) as confirme,
                    SUM(CASE WHEN statut = 'mitige' THEN 1 ELSE 0 END) as mitige,
                    SUM(CASE WHEN statut = 'faux_positif' THEN 1 ELSE 0 END) as faux_positif,
                    SUM(CASE WHEN statut = 'nouveau' THEN 1 ELSE 0 END) as nouveau,
                    SUM(CASE WHEN statut = 'en_analyse' THEN 1 ELSE 0 END) as en_analyse,
                    SUM(CASE WHEN statut = 'patche' THEN 1 ELSE 0 END) as patche,
                    SUM(CASE WHEN priorite = 'critique' THEN 1 ELSE 0 END) as critique,
                    SUM(CASE WHEN priorite = 'haute' THEN 1 ELSE 0 END) as haute,
                    SUM(CASE WHEN priorite = 'moyenne' THEN 1 ELSE 0 END) as moyenne,
                    SUM(CASE WHEN priorite = 'basse' THEN 1 ELSE 0 END) as basse
                FROM correlations
            """)
            return cursor.fetchone()
    finally:
        conn.close()


@router.get("/")
def list_correlations(
    response: Response,
    limit: int = Query(50, ge=1),
    skip: int = Query(0, ge=0),
    statut: List[str] = Query(default=[]),
    priorite: List[str] = Query(default=[]),
    asset_id: Optional[int] = None,
    client_id: Optional[int] = None,
    site_id: Optional[int] = None,
    equipment_type_id: Optional[int] = None,
    vendor_id: Optional[int] = None,
    model_id: Optional[int] = None,
    os_nom: Optional[str] = None,
    version_os: Optional[str] = None,
    firmware: Optional[str] = None,
    asset_nom: Optional[str] = None,
    cve_id: Optional[str] = None,
    nolimit: bool = False
):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            where_clauses = []
            params = []

            if statut:
                placeholders = ",".join(["%s"] * len(statut))
                where_clauses.append(f"co.statut IN ({placeholders})")
                params.extend(statut)

            if priorite:
                placeholders = ",".join(["%s"] * len(priorite))
                where_clauses.append(f"co.priorite IN ({placeholders})")
                params.extend(priorite)

            if asset_id:
                where_clauses.append("co.asset_id = %s")
                params.append(asset_id)

            if client_id:
                where_clauses.append("cl.id = %s")
                params.append(client_id)

            if site_id:
                where_clauses.append("s.id = %s")
                params.append(site_id)

            if equipment_type_id:
                where_clauses.append("a.equipment_type_id = %s")
                params.append(equipment_type_id)

            if vendor_id:
                where_clauses.append("a.vendor_id = %s")
                params.append(vendor_id)

            if model_id:
                where_clauses.append("a.model_id = %s")
                params.append(model_id)

            if os_nom:
                where_clauses.append("ov.os_nom LIKE %s")
                params.append(f"%{os_nom}%")

            if version_os:
                where_clauses.append("(a.version_os LIKE %s OR ov.version LIKE %s)")
                params.extend([f"%{version_os}%", f"%{version_os}%"])

            if firmware:
                where_clauses.append("fwv.os_nom LIKE %s")
                params.append(f"%{firmware}%")

            if asset_nom:
                where_clauses.append("a.nom_interne LIKE %s")
                params.append(f"%{asset_nom}%")

            if cve_id:
                where_clauses.append("co.cve_id LIKE %s")
                params.append(f"%{cve_id}%")

            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            joins = """
                JOIN assets a ON a.id = co.asset_id
                JOIN sites s ON s.id = a.site_id
                JOIN clients cl ON cl.id = s.client_id
                LEFT JOIN cve cv ON cv.cve_id = co.cve_id
                LEFT JOIN os_versions ov ON ov.id = a.os_version_id
                LEFT JOIN os_versions fwv ON fwv.id = a.fw_version_id
            """

            cursor.execute(f"""
                SELECT COUNT(*) as total
                FROM correlations co
                {joins}
                {where_sql}
            """, params)
            total_count = cursor.fetchone()["total"]
            response.headers["X-Total-Count"] = str(total_count)

            limit_sql = ""
            limit_params = []
            if not nolimit:
                limit_sql = "LIMIT %s OFFSET %s"
                limit_params.extend([limit, skip])

            cursor.execute(f"""
                SELECT
                    co.id,
                    co.asset_id,
                    co.cve_id,
                    co.statut,
                    co.priorite,
                    co.exploitable_air_gap,
                    co.score_contextuel,
                    co.risque_reel,
                    co.type_correlation,
                    co.override_utilisateur,
                    co.date_detection,
                    co.date_analyse,
                    co.date_resolution,
                    a.nom_interne AS asset_nom,
                    a.type_equipement,
                    a.version_os,
                    s.nom AS site_nom,
                    cl.nom AS client_nom,
                    cv.cvss_v3_score,
                    cv.cvss_v3_severity,
                    cv.description AS cve_description
                FROM correlations co
                {joins}
                {where_sql}
                ORDER BY
                    FIELD(co.priorite, 'critique', 'haute', 'moyenne', 'basse'),
                    co.score_contextuel DESC,
                    co.date_detection DESC
                {limit_sql}
            """, params + limit_params)
            return cursor.fetchall()
    finally:
        conn.close()

@router.get("/{correlation_id}")
def get_correlation(correlation_id: int):
    """Récupère les détails d'une corrélation spécifique"""
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT
                    co.*,
                    a.nom_interne AS asset_nom,
                    a.type_equipement,
                    a.systeme_exploitation,
                    a.version_os,
                    a.version_firmware,
                    a.niveau_criticite,
                    s.nom AS site_nom,
                    cl.nom AS client_nom,
                    cv.description AS cve_description,
                    cv.cvss_v3_score,
                    cv.cvss_v3_severity,
                    cv.cvss_v3_vector,
                    cv.date_publication,
                    cv.fabricant,
                    cv.produit
                FROM correlations co
                JOIN assets a ON a.id = co.asset_id
                JOIN sites s ON s.id = a.site_id
                JOIN clients cl ON cl.id = s.client_id
                LEFT JOIN cve cv ON cv.cve_id = co.cve_id
                WHERE co.id = %s
            """, (correlation_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Corrélation non trouvée")
            return row
    finally:
        conn.close()


@router.patch("/{correlation_id}")
def update_correlation(correlation_id: int, correlation: CorrelationUpdate):
    """Met à jour une corrélation (statut, priorité, override_utilisateur, notes)"""
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Vérifier que la corrélation existe
            cursor.execute("SELECT id FROM correlations WHERE id = %s", (correlation_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Corrélation non trouvée")

            # Construction de l'UPDATE dynamique
            update_fields = []
            params = []

            if correlation.statut is not None:
                update_fields.append("statut = %s")
                params.append(correlation.statut)

            if correlation.priorite is not None:
                update_fields.append("priorite = %s")
                params.append(correlation.priorite)

            if correlation.override_utilisateur is not None:
                update_fields.append("override_utilisateur = %s")
                params.append(correlation.override_utilisateur)

            if correlation.notes is not None:
                update_fields.append("notes = %s")
                params.append(correlation.notes)

            if not update_fields:
                raise HTTPException(status_code=400, detail="Aucun champ à mettre à jour")

            params.append(correlation_id)

            query = f"""
                UPDATE correlations
                SET {', '.join(update_fields)}
                WHERE id = %s
            """
            cursor.execute(query, params)
            conn.commit()

            return {"message": "Corrélation mise à jour avec succès", "id": correlation_id}
    finally:
        conn.close()


@router.delete("/{correlation_id}")
def delete_correlation(correlation_id: int):
    """Supprime une corrélation"""
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM correlations WHERE id = %s", (correlation_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Corrélation non trouvée")

            cursor.execute("DELETE FROM correlations WHERE id = %s", (correlation_id,))
            conn.commit()
            return {"message": "Corrélation supprimée avec succès"}
    finally:
        conn.close()


# Variable globale pour suivre le statut de la corrélation
correlation_status = {
    "running": False,
    "progress": 0,
    "message": "",
    "total": 0,
    "current": 0,
    "logs": []
}


@router.get("/run-status")
def get_correlation_status():
    """Retourne le statut de la corrélation en cours"""
    return correlation_status


@router.post("/run-correlation")
def run_correlation(background_tasks: BackgroundTasks, mode: str = "correlate"):
    """Lance la corrélation en arrière-plan (correlate, analyze, ou run-all)"""
    global correlation_status

    if correlation_status["running"]:
        raise HTTPException(status_code=409, detail="Une corrélation est déjà en cours")

    # Réinitialiser le statut
    correlation_status["running"] = True
    correlation_status["progress"] = 0
    correlation_status["message"] = "Démarrage..."
    correlation_status["total"] = 0
    correlation_status["current"] = 0
    correlation_status["logs"] = []

    # Lancer en arrière-plan
    background_tasks.add_task(execute_correlation, mode)

    return {"message": f"Corrélation '{mode}' lancée en arrière-plan", "status": "started"}


def execute_correlation(mode: str):
    """Exécute le script de corrélation"""
    global correlation_status

    try:
        script_path = str(BASE_DIR / "scripts" / "correlate_and_analyze.py")
        python_path = str(BASE_DIR / "venv" / "bin" / "python3")

        correlation_status["message"] = f"Exécution de '{mode}'..."
        correlation_status["logs"].append(f"[INFO] Démarrage de '{mode}'")
        print(f"DEBUG: execute_correlation started mode={mode}")

        # Test : ajout d'un log factice immédiat
        correlation_status["logs"].append("[DEBUG] Test log immédiat")

        # Exécuter le script en capturant la sortie ligne par ligne
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        
        process = subprocess.Popen(
            [python_path, script_path, mode],
            cwd=str(BASE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env
        )

        print(f"DEBUG: process started pid={process.pid}")

        # Lire la sortie ligne par ligne
        for line in process.stdout:
            line = line.rstrip()
            if line:
                correlation_status["logs"].append(line)
                # Limiter à 500 lignes de log
                if len(correlation_status["logs"]) > 500:
                    correlation_status["logs"].pop(0)

        process.wait()

        if process.returncode == 0:
            correlation_status["running"] = False
            correlation_status["progress"] = 100
            correlation_status["message"] = "Corrélation terminée avec succès"
            correlation_status["logs"].append("[SUCCESS] Terminé avec succès")
        else:
            correlation_status["running"] = False
            correlation_status["message"] = f"Erreur: code de retour {process.returncode}"
            correlation_status["logs"].append(f"[ERROR] Erreur: code de retour {process.returncode}")

    except subprocess.TimeoutExpired:
        correlation_status["running"] = False
        correlation_status["message"] = "Timeout: corrélation trop longue"
        correlation_status["logs"].append("[ERROR] Timeout dépassé")
    except Exception as e:
        correlation_status["running"] = False
        correlation_status["message"] = f"Erreur: {str(e)}"
        correlation_status["logs"].append(f"[ERROR] {str(e)}")
