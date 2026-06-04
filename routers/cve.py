from fastapi import APIRouter, Query, HTTPException
from typing import Optional, List
from database import get_connection
import pymysql.cursors

router = APIRouter(prefix="/api/cve", tags=["CVE"])

@router.get("/")
def list_cve(
    limit: int = Query(50, ge=1),
    skip: int = Query(0, ge=0),
    cve_id: Optional[str] = None,
    fabricant: Optional[str] = None,
    type_vulnerabilite: Optional[str] = None,
):
    """
    Liste les CVE avec filtres optionnels.
    """
    conn = get_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            where_clauses = []
            params = []

            if cve_id:
                where_clauses.append("cve.cve_id LIKE %s")
                params.append(f"%{cve_id}%")

            if fabricant:
                where_clauses.append("cve.fabricant LIKE %s")
                params.append(f"%{fabricant}%")

            if type_vulnerabilite:
                where_clauses.append("co.type_attaque = %s")
                params.append(type_vulnerabilite)

            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # Compter le total (DISTINCT pour éviter les doublons)
            cur.execute(f"""
                SELECT COUNT(DISTINCT cve.id) as total
                FROM cve
                LEFT JOIN correlations co ON cve.cve_id = co.cve_id
                {where_sql}
            """, params)
            total = cur.fetchone()["total"]

            # Récupérer les données avec jointure pour type_attaque
            cur.execute(f"""
                SELECT DISTINCT
                    cve.id, cve.cve_id, cve.description, cve.cvss_v3_score, cve.cvss_v3_severity,
                    cve.fabricant, cve.produit, co.type_attaque, cve.date_publication
                FROM cve
                LEFT JOIN correlations co ON cve.cve_id = co.cve_id
                {where_sql}
                ORDER BY cve.date_publication DESC
                LIMIT %s OFFSET %s
            """, params + [limit, skip])

            return {
                "total": total,
                "items": cur.fetchall()
            }
    finally:
        conn.close()

@router.get("/types")
def get_vulnerability_types():
    """
    Retourne la liste des types de vulnérabilités uniques depuis la table correlations.
    """
    conn = get_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("""
                SELECT DISTINCT type_attaque
                FROM correlations
                WHERE type_attaque IS NOT NULL
                ORDER BY type_attaque
            """)
            return {"types": [row["type_attaque"] for row in cur.fetchall()]}
    finally:
        conn.close()

@router.get("/fabricants")
def get_fabricants():
    """
    Retourne la liste des fabricants uniques.
    """
    conn = get_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("""
                SELECT DISTINCT fabricant
                FROM cve
                WHERE fabricant IS NOT NULL
                ORDER BY fabricant
            """)
            return {"fabricants": [row["fabricant"] for row in cur.fetchall()]}
    finally:
        conn.close()