"""
routers/models.py — CRUD pour le référentiel modèles/produits (product_models)
"""

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field
from typing import Optional, List
from database import get_connection

router = APIRouter(prefix="/models", tags=["Référentiel Modèles"])


# ──────────────────────────────────────────────
#  Schémas Pydantic
# ──────────────────────────────────────────────
class ModelCreate(BaseModel):
    vendor_id: int = Field(..., description="ID du fabricant")
    nom: str = Field(..., description="Nom affiché : 'Windows 11', 'DSM'")
    nvd_product: str = Field(..., description="Nom NVD lowercase : 'windows_11', 'diskstation_manager'")
    type_produit: str = Field("os", description="os, firmware, application, hardware")
    cpe_base: Optional[str] = Field(None, description="CPE sans version : cpe:2.3:o:microsoft:windows_11")
    notes: Optional[str] = None

class ModelUpdate(BaseModel):
    vendor_id: Optional[int] = None
    nom: Optional[str] = None
    nvd_product: Optional[str] = None
    type_produit: Optional[str] = None
    cpe_base: Optional[str] = None
    notes: Optional[str] = None

class ModelResponse(BaseModel):
    id: int
    vendor_id: int
    vendor_nom: str
    nom: str
    nvd_product: str
    type_produit: str
    cpe_base: Optional[str]
    notes: Optional[str]
    asset_count: int
    created_at: str
    updated_at: str

class ModelListResponse(BaseModel):
    total: int
    models: List[ModelResponse]


# ──────────────────────────────────────────────
#  Helper : construire un ModelResponse
# ──────────────────────────────────────────────
def _row_to_response(row) -> ModelResponse:
    return ModelResponse(
        id=row["id"],
        vendor_id=row["vendor_id"],
        vendor_nom=row["vendor_nom"],
        nom=row["nom"],
        nvd_product=row["nvd_product"],
        type_produit=row["type_produit"],
        cpe_base=row["cpe_base"],
        notes=row["notes"],
        asset_count=row.get("asset_count", 0),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"])
    )


BASE_SELECT = """
    SELECT pm.*,
           pv.nom AS vendor_nom,
           COUNT(a.id) AS asset_count
    FROM product_models pm
    JOIN product_vendors pv ON pv.id = pm.vendor_id
    LEFT JOIN assets a ON a.model_id = pm.id
"""


# ──────────────────────────────────────────────
#  GET /models — Lister tous les modèles
# ──────────────────────────────────────────────
@router.get("", response_model=ModelListResponse)
def list_models(
    response: Response,
    search: Optional[str] = Query(None, description="Recherche par nom ou nvd_product"),
    vendor_id: Optional[int] = Query(None, description="Filtrer par fabricant"),
    type_produit: Optional[str] = Query(None, description="Filtrer par type : os, firmware, application, hardware"),
    limit: int = Query(20, ge=1),
    skip: int = Query(0, ge=0),
    nolimit: bool = False
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            conditions = []
            params = []

            if search:
                conditions.append("(pm.nom LIKE %s OR pm.nvd_product LIKE %s)")
                params.extend([f"%{search}%", f"%{search}%"])

            if vendor_id:
                conditions.append("pm.vendor_id = %s")
                params.append(vendor_id)

            if type_produit:
                conditions.append("pm.type_produit = %s")
                params.append(type_produit)

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

            # 1. Total count
            cur.execute(f"SELECT COUNT(*) as total FROM product_models pm {where_clause}", params)
            total_count = cur.fetchone()["total"]
            response.headers["X-Total-Count"] = str(total_count)

            # 2. Paginated data
            limit_sql = ""
            if not nolimit:
                limit_sql = "LIMIT %s OFFSET %s"
                params.extend([limit, skip])

            cur.execute(f"""
                {BASE_SELECT}
                {where_clause}
                GROUP BY pm.id
                ORDER BY pv.nom, pm.nom
                {limit_sql}
            """, params)

            rows = cur.fetchall()
            models = [_row_to_response(row) for row in rows]

            return ModelListResponse(total=total_count, models=models)
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  GET /models/{id} — Détail d'un modèle
# ──────────────────────────────────────────────
@router.get("/{model_id}", response_model=ModelResponse)
def get_model(model_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(f"""
                {BASE_SELECT}
                WHERE pm.id = %s
                GROUP BY pm.id
            """, (model_id,))
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail=f"Model {model_id} introuvable")

            return _row_to_response(row)
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  POST /models — Créer un modèle
# ──────────────────────────────────────────────
@router.post("", response_model=ModelResponse, status_code=201)
def create_model(model: ModelCreate):
    nvd_product_clean = model.nvd_product.strip().lower().replace(" ", "_")

    # Valider type_produit
    valid_types = ("os", "firmware", "application", "hardware")
    if model.type_produit not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"type_produit invalide. Valeurs acceptées : {valid_types}"
        )

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Vérifier que le vendor existe
            cur.execute("SELECT id FROM product_vendors WHERE id = %s", (model.vendor_id,))
            if not cur.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail=f"Vendor {model.vendor_id} introuvable"
                )

            # Vérifier unicité vendor + product
            cur.execute(
                "SELECT id FROM product_models WHERE vendor_id = %s AND nvd_product = %s",
                (model.vendor_id, nvd_product_clean)
            )
            if cur.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail=f"Le produit '{nvd_product_clean}' existe déjà pour ce vendor"
                )

            # Générer le CPE de base si non fourni
            cpe_base = model.cpe_base
            if not cpe_base:
                cur.execute(
                    "SELECT nvd_vendor FROM product_vendors WHERE id = %s",
                    (model.vendor_id,)
                )
                vendor_row = cur.fetchone()
                part = "a" if model.type_produit == "application" else "o" if model.type_produit in ("os", "firmware") else "h"
                cpe_base = f"cpe:2.3:{part}:{vendor_row['nvd_vendor']}:{nvd_product_clean}"

            cur.execute("""
                INSERT INTO product_models (vendor_id, nom, nvd_product, type_produit, cpe_base, notes)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                model.vendor_id,
                model.nom.strip(),
                nvd_product_clean,
                model.type_produit,
                cpe_base,
                model.notes
            ))
            conn.commit()
            new_id = cur.lastrowid

        return get_model(new_id)
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  PUT /models/{id} — Modifier un modèle
# ──────────────────────────────────────────────
@router.put("/{model_id}", response_model=ModelResponse)
def update_model(model_id: int, model: ModelUpdate):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM product_models WHERE id = %s", (model_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail=f"Model {model_id} introuvable")

            updates = []
            values = []

            if model.vendor_id is not None:
                cur.execute("SELECT id FROM product_vendors WHERE id = %s", (model.vendor_id,))
                if not cur.fetchone():
                    raise HTTPException(status_code=404, detail=f"Vendor {model.vendor_id} introuvable")
                updates.append("vendor_id = %s")
                values.append(model.vendor_id)

            if model.nom is not None:
                updates.append("nom = %s")
                values.append(model.nom.strip())

            if model.nvd_product is not None:
                nvd_clean = model.nvd_product.strip().lower().replace(" ", "_")
                updates.append("nvd_product = %s")
                values.append(nvd_clean)

            if model.type_produit is not None:
                valid_types = ("os", "firmware", "application", "hardware")
                if model.type_produit not in valid_types:
                    raise HTTPException(
                        status_code=400,
                        detail=f"type_produit invalide. Valeurs acceptées : {valid_types}"
                    )
                updates.append("type_produit = %s")
                values.append(model.type_produit)

            if model.cpe_base is not None:
                updates.append("cpe_base = %s")
                values.append(model.cpe_base)

            if model.notes is not None:
                updates.append("notes = %s")
                values.append(model.notes)

            if not updates:
                raise HTTPException(status_code=400, detail="Aucun champ à modifier")

            values.append(model_id)
            cur.execute(
                f"UPDATE product_models SET {', '.join(updates)} WHERE id = %s",
                values
            )
            conn.commit()

        return get_model(model_id)
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  DELETE /models/{id} — Supprimer un modèle
# ──────────────────────────────────────────────
@router.delete("/{model_id}")
def delete_model(model_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nom FROM product_models WHERE id = %s", (model_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Model {model_id} introuvable")

            # Vérifier qu'aucun asset ne référence ce model
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM assets WHERE model_id = %s",
                (model_id,)
            )
            count = cur.fetchone()["cnt"]
            if count > 0:
                raise HTTPException(
                    status_code=409,
                    detail=f"Impossible de supprimer '{row['nom']}' : {count} asset(s) associé(s)."
                )

            cur.execute("DELETE FROM product_models WHERE id = %s", (model_id,))
            conn.commit()

            return {"message": f"Model '{row['nom']}' supprimé", "id": model_id}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  GET /models/{id}/assets — Assets utilisant ce modèle
# ──────────────────────────────────────────────
@router.get("/{model_id}/assets")
def list_model_assets(model_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nom FROM product_models WHERE id = %s", (model_id,))
            model = cur.fetchone()
            if not model:
                raise HTTPException(status_code=404, detail=f"Model {model_id} introuvable")

            cur.execute("""
                SELECT a.id, a.nom, a.hostname, a.os_version, a.firmware_version,
                       a.statut, a.criticite,
                       s.nom AS site_nom,
                       c.nom AS client_nom
                FROM assets a
                JOIN sites s ON s.id = a.site_id
                JOIN clients c ON c.id = s.client_id
                WHERE a.model_id = %s
                ORDER BY c.nom, s.nom, a.nom
            """, (model_id,))

            assets = cur.fetchall()

            return {
                "model_id": model_id,
                "model_nom": model["nom"],
                "total": len(assets),
                "assets": assets
            }
    finally:
        conn.close()
