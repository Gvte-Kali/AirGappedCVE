"""
routers/vendors.py — CRUD pour le référentiel fabricants (product_vendors)
"""

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field
from typing import Optional, List
from database import get_connection

router = APIRouter(prefix="/vendors", tags=["Référentiel Fabricants"])


# ──────────────────────────────────────────────
#  Schémas Pydantic
# ──────────────────────────────────────────────
class VendorCreate(BaseModel):
    nom: str = Field(..., description="Nom affiché : 'Microsoft', 'Synology'")
    nvd_vendor: str = Field(..., description="Nom NVD lowercase : 'microsoft', 'synology'")
    notes: Optional[str] = None

class VendorUpdate(BaseModel):
    nom: Optional[str] = None
    nvd_vendor: Optional[str] = None
    notes: Optional[str] = None

class VendorResponse(BaseModel):
    id: int
    nom: str
    nvd_vendor: str
    notes: Optional[str]
    created_at: str
    updated_at: str
    model_count: Optional[int] = 0

class VendorListResponse(BaseModel):
    total: int
    vendors: List[VendorResponse]


# ──────────────────────────────────────────────
#  GET /vendors — Lister tous les fabricants
# ──────────────────────────────────────────────
@router.get("", response_model=VendorListResponse)
def list_vendors(
    response: Response,
    search: Optional[str] = Query(None, description="Recherche par nom ou nvd_vendor"),
    limit: int = Query(20, ge=1),
    skip: int = Query(0, ge=0),
    nolimit: bool = False
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 1. Get total count
            where_sql = ""
            params = []
            if search:
                where_sql = "WHERE pv.nom LIKE %s OR pv.nvd_vendor LIKE %s"
                params.extend([f"%{search}%", f"%{search}%"])

            cur.execute(f"SELECT COUNT(*) as total FROM product_vendors pv {where_sql}", params)
            total_count = cur.fetchone()["total"]
            response.headers["X-Total-Count"] = str(total_count)

            # 2. Get paginated data
            limit_sql = ""
            if not nolimit:
                limit_sql = "LIMIT %s OFFSET %s"
                params.extend([limit, skip])

            query = f"""
                SELECT pv.*,
                       COUNT(pm.id) AS model_count
                FROM product_vendors pv
                LEFT JOIN product_models pm ON pm.vendor_id = pv.id
                {where_sql}
                GROUP BY pv.id
                ORDER BY pv.nom
                {limit_sql}
            """
            cur.execute(query, params)

            rows = cur.fetchall()
            vendors = []
            for row in rows:
                vendors.append(VendorResponse(
                    id=row["id"],
                    nom=row["nom"],
                    nvd_vendor=row["nvd_vendor"],
                    notes=row["notes"],
                    created_at=str(row["created_at"]),
                    updated_at=str(row["updated_at"]),
                    model_count=row["model_count"]
                ))

            return VendorListResponse(total=total_count, vendors=vendors)
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  GET /vendors/{id} — Détail d'un fabricant
# ──────────────────────────────────────────────
@router.get("/{vendor_id}", response_model=VendorResponse)
def get_vendor(vendor_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT pv.*,
                       COUNT(pm.id) AS model_count
                FROM product_vendors pv
                LEFT JOIN product_models pm ON pm.vendor_id = pv.id
                WHERE pv.id = %s
                GROUP BY pv.id
            """, (vendor_id,))
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail=f"Vendor {vendor_id} introuvable")

            return VendorResponse(
                id=row["id"],
                nom=row["nom"],
                nvd_vendor=row["nvd_vendor"],
                notes=row["notes"],
                created_at=str(row["created_at"]),
                updated_at=str(row["updated_at"]),
                model_count=row["model_count"]
            )
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  POST /vendors — Créer un fabricant
# ──────────────────────────────────────────────
@router.post("", response_model=VendorResponse, status_code=201)
def create_vendor(vendor: VendorCreate):
    # Forcer le nvd_vendor en lowercase sans espaces
    nvd_vendor_clean = vendor.nvd_vendor.strip().lower().replace(" ", "_")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Vérifier unicité
            cur.execute(
                "SELECT id FROM product_vendors WHERE nvd_vendor = %s",
                (nvd_vendor_clean,)
            )
            if cur.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail=f"Le vendor NVD '{nvd_vendor_clean}' existe déjà"
                )

            cur.execute("""
                INSERT INTO product_vendors (nom, nvd_vendor, notes)
                VALUES (%s, %s, %s)
            """, (vendor.nom.strip(), nvd_vendor_clean, vendor.notes))

            conn.commit()
            new_id = cur.lastrowid

        # Retourner le vendor créé
        return get_vendor(new_id)
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  PUT /vendors/{id} — Modifier un fabricant
# ──────────────────────────────────────────────
@router.put("/{vendor_id}", response_model=VendorResponse)
def update_vendor(vendor_id: int, vendor: VendorUpdate):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Vérifier existence
            cur.execute("SELECT id FROM product_vendors WHERE id = %s", (vendor_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail=f"Vendor {vendor_id} introuvable")

            # Construire la requête dynamiquement (que les champs fournis)
            updates = []
            values = []

            if vendor.nom is not None:
                updates.append("nom = %s")
                values.append(vendor.nom.strip())

            if vendor.nvd_vendor is not None:
                nvd_clean = vendor.nvd_vendor.strip().lower().replace(" ", "_")
                # Vérifier unicité du nouveau nvd_vendor
                cur.execute(
                    "SELECT id FROM product_vendors WHERE nvd_vendor = %s AND id != %s",
                    (nvd_clean, vendor_id)
                )
                if cur.fetchone():
                    raise HTTPException(
                        status_code=409,
                        detail=f"Le vendor NVD '{nvd_clean}' est déjà utilisé"
                    )
                updates.append("nvd_vendor = %s")
                values.append(nvd_clean)

            if vendor.notes is not None:
                updates.append("notes = %s")
                values.append(vendor.notes)

            if not updates:
                raise HTTPException(status_code=400, detail="Aucun champ à modifier")

            values.append(vendor_id)
            cur.execute(
                f"UPDATE product_vendors SET {', '.join(updates)} WHERE id = %s",
                values
            )
            conn.commit()

        return get_vendor(vendor_id)
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  DELETE /vendors/{id} — Supprimer un fabricant
# ──────────────────────────────────────────────
@router.delete("/{vendor_id}")
def delete_vendor(vendor_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Vérifier existence
            cur.execute("SELECT id, nom FROM product_vendors WHERE id = %s", (vendor_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Vendor {vendor_id} introuvable")

            # Vérifier qu'aucun model ne dépend de ce vendor
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM product_models WHERE vendor_id = %s",
                (vendor_id,)
            )
            count = cur.fetchone()["cnt"]
            if count > 0:
                raise HTTPException(
                    status_code=409,
                    detail=f"Impossible de supprimer '{row['nom']}' : {count} modèle(s) associé(s). Supprimez d'abord les modèles."
                )

            # Vérifier qu'aucun asset ne référence ce vendor
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM assets WHERE vendor_id = %s",
                (vendor_id,)
            )
            count = cur.fetchone()["cnt"]
            if count > 0:
                raise HTTPException(
                    status_code=409,
                    detail=f"Impossible de supprimer '{row['nom']}' : {count} asset(s) associé(s)."
                )

            cur.execute("DELETE FROM product_vendors WHERE id = %s", (vendor_id,))
            conn.commit()

            return {"message": f"Vendor '{row['nom']}' supprimé", "id": vendor_id}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  GET /vendors/{id}/models — Modèles d'un fabricant
# ──────────────────────────────────────────────
@router.get("/{vendor_id}/models")
def list_vendor_models(vendor_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nom FROM product_vendors WHERE id = %s", (vendor_id,))
            vendor = cur.fetchone()
            if not vendor:
                raise HTTPException(status_code=404, detail=f"Vendor {vendor_id} introuvable")

            cur.execute("""
                SELECT pm.*,
                       COUNT(a.id) AS asset_count
                FROM product_models pm
                LEFT JOIN assets a ON a.model_id = pm.id
                WHERE pm.vendor_id = %s
                GROUP BY pm.id
                ORDER BY pm.nom
            """, (vendor_id,))

            models = cur.fetchall()

            return {
                "vendor_id": vendor_id,
                "vendor_nom": vendor["nom"],
                "total": len(models),
                "models": models
            }
    finally:
        conn.close()
