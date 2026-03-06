from fastapi import APIRouter, HTTPException, Response, Query
from pydantic import BaseModel
from typing import Optional
from database import get_connection

router = APIRouter()

# ─── Schémas Pydantic ───────────────────────────────────────────────────────

class ClientCreate(BaseModel):
    nom: str
    contact_nom: Optional[str] = None
    contact_email: Optional[str] = None
    contact_telephone: Optional[str] = None
    notes: Optional[str] = None

class ClientUpdate(BaseModel):
    nom: Optional[str] = None
    contact_nom: Optional[str] = None
    contact_email: Optional[str] = None
    contact_telephone: Optional[str] = None
    notes: Optional[str] = None

# ─── Endpoints ──────────────────────────────────────────────────────────────

@router.get("/")
def list_clients(
    response: Response,
    limit: int = Query(20, ge=1),
    skip: int = Query(0, ge=0),
    nolimit: bool = False
):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # 1. Get total count
            cursor.execute("SELECT COUNT(*) as total FROM clients")
            total_count = cursor.fetchone()["total"]
            response.headers["X-Total-Count"] = str(total_count)

            # 2. Get data
            limit_sql = ""
            params = []
            if not nolimit:
                limit_sql = "LIMIT %s OFFSET %s"
                params.extend([limit, skip])

            query = f"""
                SELECT
                    c.id,
                    c.nom,
                    c.contact_nom,
                    c.contact_email,
                    c.contact_telephone,
                    c.notes,
                    c.date_creation,
                    c.date_modification,
                    COUNT(DISTINCT s.id)  AS nb_sites,
                    COUNT(DISTINCT a.id)  AS nb_assets
                FROM clients c
                LEFT JOIN sites s  ON s.client_id = c.id
                LEFT JOIN assets a ON a.site_id   = s.id
                GROUP BY c.id
                ORDER BY c.nom ASC
                {limit_sql}
            """
            cursor.execute(query, params)
            return cursor.fetchall()
    finally:
        conn.close()


@router.get("/{client_id}")
def get_client(client_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT
                    c.*,
                    COUNT(DISTINCT s.id)  AS nb_sites,
                    COUNT(DISTINCT a.id)  AS nb_assets
                FROM clients c
                LEFT JOIN sites s  ON s.client_id = c.id
                LEFT JOIN assets a ON a.site_id   = s.id
                WHERE c.id = %s
                GROUP BY c.id
            """, (client_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Client non trouvé")
            return row
    finally:
        conn.close()


@router.post("/", status_code=201)
def create_client(client: ClientCreate):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Vérifier doublon sur le nom
            cursor.execute("SELECT id FROM clients WHERE nom = %s", (client.nom,))
            if cursor.fetchone():
                raise HTTPException(status_code=409, detail="Un client avec ce nom existe déjà")

            cursor.execute("""
                INSERT INTO clients (nom, contact_nom, contact_email, contact_telephone, notes)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                client.nom,
                client.contact_nom,
                client.contact_email,
                client.contact_telephone,
                client.notes
            ))
            conn.commit()
            return {"id": cursor.lastrowid, "message": "Client créé avec succès"}
    finally:
        conn.close()


@router.put("/{client_id}")
def update_client(client_id: int, client: ClientUpdate):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM clients WHERE id = %s", (client_id,))
            existing = cursor.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Client non trouvé")

            # Vérifier doublon sur le nom si on le change
            if client.nom and client.nom != existing["nom"]:
                cursor.execute(
                    "SELECT id FROM clients WHERE nom = %s AND id != %s",
                    (client.nom, client_id)
                )
                if cursor.fetchone():
                    raise HTTPException(status_code=409, detail="Un client avec ce nom existe déjà")

            cursor.execute("""
                UPDATE clients SET
                    nom           = %s,
                    contact_nom   = %s,
                    contact_email = %s,
                    contact_telephone   = %s,
                    notes         = %s
                WHERE id = %s
            """, (
                client.nom           if client.nom           is not None else existing["nom"],
                client.contact_nom   if client.contact_nom   is not None else existing["contact_nom"],
                client.contact_email if client.contact_email is not None else existing["contact_email"],
                client.contact_telephone   if client.contact_telephone   is not None else existing["contact_telephone"],
                client.notes         if client.notes         is not None else existing["notes"],
                client_id
            ))
            conn.commit()
            return {"message": "Client mis à jour avec succès"}
    finally:
        conn.close()


@router.delete("/{client_id}")
def delete_client(client_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM clients WHERE id = %s", (client_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Client non trouvé")

            # Vérifier qu'il n'a pas de sites rattachés
            cursor.execute("SELECT COUNT(*) AS nb FROM sites WHERE client_id = %s", (client_id,))
            nb = cursor.fetchone()["nb"]
            if nb > 0:
                raise HTTPException(
                    status_code=409,
                    detail=f"Impossible de supprimer : {nb} site(s) rattaché(s) à ce client"
                )

            cursor.execute("DELETE FROM clients WHERE id = %s", (client_id,))
            conn.commit()
            return {"message": "Client supprimé avec succès"}
    finally:
        conn.close()

