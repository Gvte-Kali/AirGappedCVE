from fastapi import APIRouter, Query, HTTPException
from typing import Optional, List
from database import get_connection
import pymysql.cursors

router = APIRouter(prefix="/api/cve", tags=["CVE"])

@router.get("/")
def list_cve(
    limit: int = Query(10, ge=1),
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

            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # 1. Compter le total SANS jointure (ultra-rapide)
            cur.execute(f"""
                SELECT COUNT(*) as total
                FROM cve
                {where_sql}
            """, params)
            total = cur.fetchone()["total"]

            # 2. Récupérer les données avec sous-requête pour type_attaque (pas de DISTINCT)
            #    Si type_vulnerabilite est fourni, ajoute le filtre dans la sous-requête
            if type_vulnerabilite:
                where_sql_with_type = f"{where_sql} AND EXISTS (SELECT 1 FROM correlations co WHERE co.cve_id = cve.cve_id AND co.type_attaque = %s)"
                params_with_type = params + [type_vulnerabilite]
                cur.execute(f"""
                    SELECT
                        cve.id, cve.cve_id, cve.description, cve.cvss_v3_score, cve.cvss_v3_severity,
                        cve.fabricant, cve.produit, cve.date_publication,
                        (
                            SELECT co.type_attaque
                            FROM correlations co
                            WHERE co.cve_id = cve.cve_id
                            AND co.type_attaque = %s
                            LIMIT 1
                        ) as type_attaque
                    FROM cve
                    {where_sql_with_type}
                    ORDER BY cve.date_publication DESC
                    LIMIT %s OFFSET %s
                """, params_with_type + [limit, skip])
            else:
                cur.execute(f"""
                    SELECT
                        cve.id, cve.cve_id, cve.description, cve.cvss_v3_score, cve.cvss_v3_severity,
                        cve.fabricant, cve.produit, cve.date_publication,
                        (
                            SELECT co.type_attaque
                            FROM correlations co
                            WHERE co.cve_id = cve.cve_id
                            LIMIT 1
                        ) as type_attaque
                    FROM cve
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

@router.get("/{cve_id}")
def get_cve_details(cve_id: str):
    """
    Retourne les détails complets d'une CVE par son ID.
    """
    conn = get_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            # Récupère les infos de base depuis cve
            cur.execute("""
                SELECT cve_id, description, cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
                       fabricant, produit, type_attaque, date_publication, references
                FROM cve
                WHERE cve_id = %s
            """, (cve_id,))
            cve = cur.fetchone()
            if not cve:
                raise HTTPException(status_code=404, detail="CVE non trouvée")

            # Formate les références (si stockées sous forme de JSON)
            if cve.get('references'):
                try:
                    cve['references'] = json.loads(cve['references'])
                except:
                    cve['references'] = []

            return cve
    finally:
        conn.close()