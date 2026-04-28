from fastapi import APIRouter, HTTPException, Response, Query
from pydantic import BaseModel
from typing import Optional
from database import get_connection

router = APIRouter()


# ── Schémas Pydantic ──────────────────────────────────────────
class SiteCreate(BaseModel):
    client_id: int
    nom: str
    adresse: Optional[str] = None
    ville: Optional[str] = None
    code_postal: Optional[str] = None
    pays: Optional[str] = "France"
    contact_local_nom: Optional[str] = None
    contact_local_email: Optional[str] = None
    contact_local_telephone: Optional[str] = None
    notes: Optional[str] = None
    actif: Optional[bool] = True


class SiteUpdate(BaseModel):
    client_id: Optional[int] = None
    nom: Optional[str] = None
    adresse: Optional[str] = None
    ville: Optional[str] = None
    code_postal: Optional[str] = None
    pays: Optional[str] = None
    contact_local_nom: Optional[str] = None
    contact_local_email: Optional[str] = None
    contact_local_telephone: Optional[str] = None
    notes: Optional[str] = None
    actif: Optional[bool] = None


# ── Endpoints ─────────────────────────────────────────────────
@router.get("/")
def list_sites(
    response: Response,
    client_id: Optional[int] = None,
    site_id: Optional[int] = None,
    actif: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(20, ge=1),
    skip: int = Query(0, ge=0)
):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            where_clauses = []
            params_where = []
            if client_id is not None:
                where_clauses.append("s.client_id = %s")
                params_where.append(client_id)
            if site_id is not None:
                where_clauses.append("s.id = %s")
                params_where.append(site_id)
            if actif is not None:
                where_clauses.append("s.actif = %s")
                params_where.append(1 if actif else 0)
            if search:
                where_clauses.append("s.nom LIKE %s")
                params_where.append(f"%{search}%")
            where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

            # 1. Total count
            cursor.execute(f"SELECT COUNT(*) as total FROM sites s {where_sql}", params_where)
            total_count = cursor.fetchone()["total"]
            response.headers["X-Total-Count"] = str(total_count)

            # 2. Paginated data
            params = params_where + [limit, skip]
            limit_sql = "LIMIT %s OFFSET %s"

            query = f"""
                SELECT
                    s.id,
                    s.nom,
                    s.adresse,
                    s.ville,
                    s.code_postal,
                    s.pays,
                    s.contact_local_nom,
                    s.contact_local_email,
                    s.contact_local_telephone,
                    s.notes,
                    s.actif,
                    s.date_creation,
                    s.date_modification,
                    s.client_id,
                    c.nom AS client_nom,
                    COUNT(DISTINCT a.id) AS nb_assets
                FROM sites s
                JOIN clients c     ON s.client_id = c.id
                LEFT JOIN assets a ON a.site_id   = s.id
                {where_sql}
                GROUP BY s.id
                ORDER BY c.nom ASC, s.nom ASC
                {limit_sql}
            """
            cursor.execute(query, params)
            return cursor.fetchall()
    finally:
        conn.close()


@router.get("/{site_id}")
def get_site(site_id: int):
    """Retourne un site par son ID."""
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT s.*, c.nom as client_nom
                FROM sites s
                JOIN clients c ON s.client_id = c.id
                WHERE s.id = %s
                """,
                (site_id,),
            )
            site = cursor.fetchone()
            if not site:
                raise HTTPException(status_code=404, detail="Site non trouvé")
            return site
    finally:
        conn.close()


@router.post("/", status_code=201)
def create_site(site: SiteCreate):
    """Crée un nouveau site."""
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Vérifie que le client existe
            cursor.execute("SELECT id FROM clients WHERE id = %s", (site.client_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Client non trouvé")

            cursor.execute(
                """
                INSERT INTO sites (
                    client_id, nom, adresse, ville, code_postal, pays,
                    contact_local_nom, contact_local_email, contact_local_telephone,
                    notes, actif
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    site.client_id,
                    site.nom,
                    site.adresse,
                    site.ville,
                    site.code_postal,
                    site.pays,
                    site.contact_local_nom,
                    site.contact_local_email,
                    site.contact_local_telephone,
                    site.notes,
                    site.actif,
                ),
            )
            conn.commit()
            new_id = cursor.lastrowid
            cursor.execute(
                """
                SELECT s.*, c.nom as client_nom
                FROM sites s
                JOIN clients c ON s.client_id = c.id
                WHERE s.id = %s
                """,
                (new_id,),
            )
            return cursor.fetchone()
    finally:
        conn.close()


@router.put("/{site_id}")
def update_site(site_id: int, site: SiteUpdate):
    """Met à jour un site existant."""
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM sites WHERE id = %s", (site_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Site non trouvé")

            fields = site.model_dump(exclude_none=True)
            if not fields:
                raise HTTPException(status_code=400, detail="Aucun champ à mettre à jour")

            # Si client_id est modifié, vérifie qu'il existe
            if "client_id" in fields:
                cursor.execute(
                    "SELECT id FROM clients WHERE id = %s", (fields["client_id"],)
                )
                if not cursor.fetchone():
                    raise HTTPException(status_code=404, detail="Client non trouvé")

            set_clause = ", ".join(f"{k} = %s" for k in fields)
            values = list(fields.values()) + [site_id]

            cursor.execute(
                f"UPDATE sites SET {set_clause} WHERE id = %s", values
            )
            conn.commit()
            cursor.execute(
                """
                SELECT s.*, c.nom as client_nom
                FROM sites s
                JOIN clients c ON s.client_id = c.id
                WHERE s.id = %s
                """,
                (site_id,),
            )
            return cursor.fetchone()
    finally:
        conn.close()


@router.delete("/{site_id}", status_code=204)
def delete_site(site_id: int):
    """Supprime un site."""
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM sites WHERE id = %s", (site_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Site non trouvé")
            cursor.execute("DELETE FROM sites WHERE id = %s", (site_id,))
            conn.commit()
    finally:
        conn.close()

