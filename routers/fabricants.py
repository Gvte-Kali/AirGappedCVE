from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from database import get_connection

router = APIRouter(prefix="/api/fabricants", tags=["fabricants"])


class FabricantIn(BaseModel):
    nom: str
    notes: Optional[str] = None


class FabricantOut(FabricantIn):
    id: int
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


# ── Liste / Recherche ──────────────────────────────────────
@router.get("")
def lister_fabricants(q: Optional[str] = Query(None)):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    if q:
        cur.execute(
            """SELECT f.*, COUNT(m.id) AS nb_modeles
               FROM fabricants f LEFT JOIN modeles m ON m.fabricant_id = f.id
               WHERE f.nom LIKE %s
               GROUP BY f.id ORDER BY f.nom LIMIT 50""",
            (f"%{q}%",),
        )
    else:
        cur.execute(
            """SELECT f.*, COUNT(m.id) AS nb_modeles
               FROM fabricants f LEFT JOIN modeles m ON m.fabricant_id = f.id
               GROUP BY f.id ORDER BY f.nom"""
        )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows



# ── Détail ─────────────────────────────────────────────────
@router.get("/{fabricant_id}")
def get_fabricant(fabricant_id: int):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM fabricants WHERE id = %s", (fabricant_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(404, "Fabricant introuvable")
    return row


# ── Création ───────────────────────────────────────────────
@router.post("", status_code=201)
def creer_fabricant(data: FabricantIn):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO fabricants (nom, notes) VALUES (%s, %s)",
            (data.nom.strip(), data.notes),
        )
        conn.commit()
        new_id = cur.lastrowid
    except Exception as e:
        conn.rollback()
        if "Duplicate" in str(e):
            raise HTTPException(409, "Ce fabricant existe déjà")
        raise HTTPException(500, str(e))
    finally:
        cur.close()
        conn.close()
    return {"id": new_id, "nom": data.nom.strip()}


# ── Modification ───────────────────────────────────────────
@router.put("/{fabricant_id}")
def modifier_fabricant(fabricant_id: int, data: FabricantIn):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE fabricants SET nom = %s, notes = %s WHERE id = %s",
        (data.nom.strip(), data.notes, fabricant_id),
    )
    conn.commit()
    affected = cur.rowcount
    cur.close()
    conn.close()
    if not affected:
        raise HTTPException(404, "Fabricant introuvable")
    return {"message": "ok"}


# ── Suppression ────────────────────────────────────────────
@router.delete("/{fabricant_id}")
def supprimer_fabricant(fabricant_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM fabricants WHERE id = %s", (fabricant_id,))
    conn.commit()
    affected = cur.rowcount
    cur.close()
    conn.close()
    if not affected:
        raise HTTPException(404, "Fabricant introuvable")
    return {"message": "ok"}