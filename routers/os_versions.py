from fastapi import APIRouter, Query, Response, HTTPException
from typing import Optional
from pydantic import BaseModel
from database import get_connection

router = APIRouter()


class OsVersionCreate(BaseModel):
    os_nom: str
    version: Optional[str] = None
    nvd_vendor: str
    nvd_product: str
    type_produit: str = "os"


@router.get("/api/os-versions")
def list_os_versions(
    response: Response,
    search: Optional[str] = Query(None),
    type_produit: Optional[str] = Query(None),
    vendor: Optional[str] = Query(None),
    limit: int = Query(50),
    skip: int = Query(0),
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            conditions = []
            params = []
            if search:
                conditions.append("(os_nom LIKE %s OR version LIKE %s OR nvd_product LIKE %s)")
                params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
            if type_produit:
                conditions.append("type_produit = %s")
                params.append(type_produit)
            if vendor:
                conditions.append("nvd_vendor = %s")
                params.append(vendor)
            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

            cur.execute(f"SELECT COUNT(*) as total FROM os_versions {where}", params)
            total = cur.fetchone()["total"]
            response.headers["X-Total-Count"] = str(total)

            cur.execute(f"""
                SELECT id, os_nom, version, nvd_vendor, nvd_product, type_produit, created_at
                FROM os_versions
                {where}
                ORDER BY os_nom ASC, version ASC
                LIMIT %s OFFSET %s
            """, params + [limit, skip])

            rows = cur.fetchall()
            for row in rows:
                v = row["version"] or ""
                row["label"] = f"{row['os_nom']} {v}".strip()
            return rows
    finally:
        conn.close()


class OsVersionUpdate(BaseModel):
    os_nom: Optional[str] = None
    version: Optional[str] = None
    nvd_vendor: Optional[str] = None
    nvd_product: Optional[str] = None
    type_produit: Optional[str] = None


@router.put("/api/os-versions/{id}")
def update_os_version(id: int, entry: OsVersionUpdate):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM os_versions WHERE id = %s", (id,))
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Entrée non trouvée")
            cur.execute("""
                UPDATE os_versions SET
                    os_nom      = %s,
                    version     = %s,
                    nvd_vendor  = %s,
                    nvd_product = %s,
                    type_produit= %s
                WHERE id = %s
            """, (
                entry.os_nom       or existing["os_nom"],
                entry.version      if entry.version is not None else existing["version"],
                entry.nvd_vendor   or existing["nvd_vendor"],
                entry.nvd_product  or existing["nvd_product"],
                entry.type_produit or existing["type_produit"],
                id
            ))
            conn.commit()
            return {"message": "Entrée mise à jour"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@router.post("/api/os-versions", status_code=201)
def create_os_version(entry: OsVersionCreate):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Log des valeurs reçues
            print(f"DEBUG: Received data - os_nom: {entry.os_nom}, version: {entry.version}, nvd_vendor: {entry.nvd_vendor}, nvd_product: {entry.nvd_product}, type_produit: {entry.type_produit}")

            # Vérification de l'unicité
            cur.execute("""
                SELECT id FROM os_versions
                WHERE nvd_vendor = %s AND nvd_product = %s AND version = %s
            """, (entry.nvd_vendor, entry.nvd_product, entry.version))
            existing = cur.fetchone()
            if existing:
                print(f"DEBUG: Duplicate found - ID: {existing['id']}")
                raise HTTPException(
                    status_code=409,
                    detail="Cette combinaison vendor/produit/version existe déjà dans le référentiel."
                )

            # Log de la requête d'insertion
            insert_query = """
                INSERT INTO os_versions (os_nom, version, nvd_vendor, nvd_product, type_produit)
                VALUES (%s, %s, %s, %s, %s)
            """
            print(f"DEBUG: Insert query - {insert_query} with params: {entry.os_nom}, {entry.version}, {entry.nvd_vendor}, {entry.nvd_product}, {entry.type_produit}")

            cur.execute(insert_query, (entry.os_nom, entry.version, entry.nvd_vendor, entry.nvd_product, entry.type_produit))
            conn.commit()
            return {"id": cur.lastrowid, "message": "Entrée créée"}
    except Exception as e:
        print(f"DEBUG: Error - {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@router.get("/api/os-versions/vendors")
def list_os_vendors():
    """Liste les vendors distincts pour le filtre."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT nvd_vendor FROM os_versions ORDER BY nvd_vendor")
            return [row["nvd_vendor"] for row in cur.fetchall()]
    finally:
        conn.close()
