from fastapi import APIRouter, HTTPException, Response, Query
from pydantic import BaseModel
from typing import Optional
from database import get_connection

router = APIRouter()


# ── Modèles Pydantic ──────────────────────────────────────────────

class AssetCreate(BaseModel):
    site_id: int
    nom_interne: str
    type_equipement: Optional[str] = None
    equipment_type_id: Optional[int] = None
    vendor_id: Optional[int] = None
    model_id: Optional[int] = None
    os_version_id: Optional[int] = None
    fw_version_id: Optional[int] = None
    bios_version_id: Optional[int] = None
    numero_serie: Optional[str] = None
    adresse_ip: Optional[str] = None
    adresse_mac: Optional[str] = None
    hostname: Optional[str] = None
    systeme_exploitation: Optional[str] = None
    version_os: Optional[str] = None
    version_firmware: Optional[str] = None
    version_bios: Optional[str] = None
    date_installation: Optional[str] = None
    date_fin_garantie: Optional[str] = None
    niveau_criticite: Optional[str] = "moyen"
    statut_operationnel: Optional[str] = "actif"
    proprietes_specifiques: Optional[str] = None
    notes: Optional[str] = None


class AssetUpdate(BaseModel):
    site_id: Optional[int] = None
    nom_interne: Optional[str] = None
    type_equipement: Optional[str] = None
    equipment_type_id: Optional[int] = None
    vendor_id: Optional[int] = None
    model_id: Optional[int] = None
    os_version_id: Optional[int] = None
    fw_version_id: Optional[int] = None
    bios_version_id: Optional[int] = None
    numero_serie: Optional[str] = None
    adresse_ip: Optional[str] = None
    adresse_mac: Optional[str] = None
    hostname: Optional[str] = None
    systeme_exploitation: Optional[str] = None
    version_os: Optional[str] = None
    version_firmware: Optional[str] = None
    version_bios: Optional[str] = None
    date_installation: Optional[str] = None
    date_fin_garantie: Optional[str] = None
    niveau_criticite: Optional[str] = None
    statut_operationnel: Optional[str] = None
    proprietes_specifiques: Optional[str] = None
    notes: Optional[str] = None


# ── GET / ──────────────────────────────────────────────────────────

@router.get("/")
def list_assets(
    response: Response,
    limit: int = Query(20, ge=1),
    skip: int = Query(0, ge=0),
    nolimit: bool = False,
    client_id: Optional[int] = None,
    site_id: Optional[int] = None,
    type_equipement: Optional[str] = None
):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Build WHERE clause dynamically based on filters
            where_clauses = []
            params = []
            
            if client_id is not None:
                where_clauses.append("c.id = %s")
                params.append(client_id)
            if site_id is not None:
                where_clauses.append("s.id = %s")
                params.append(site_id)
            if type_equipement is not None:
                where_clauses.append("a.type_equipement = %s")
                params.append(type_equipement)
                
            where_sql = ""
            if where_clauses:
                where_sql = "WHERE " + " AND ".join(where_clauses)
            
            # 1. Get total count
            count_query = f"""
                SELECT COUNT(*) as total
                FROM assets a
                JOIN sites s        ON a.site_id   = s.id
                JOIN clients c      ON s.client_id = c.id
                {where_sql}
            """
            cursor.execute(count_query, params)
            total_count = cursor.fetchone()["total"]
            response.headers["X-Total-Count"] = str(total_count)

            # 2. Get data
            limit_sql = ""
            if not nolimit:
                limit_sql = "LIMIT %s OFFSET %s"
                params.extend([limit, skip])
                
            query = f"""
                SELECT
                    a.id,
                    a.nom_interne,
                    a.type_equipement,
                    a.equipment_type_id,
                    et.code            AS type_equipement_code,
                    et.label           AS type_equipement_label,
                    a.vendor_id,
                    v.nom            AS vendor_nom,
                    a.model_id,
                    m.nom            AS model_nom,
                    a.os_version_id,
                    ov.os_nom        AS os_version_nom,
                    ov.version       AS os_version_ver,
                    ov.nvd_product   AS os_nvd_product,
                    a.fw_version_id,
                    fw.os_nom        AS fw_version_nom,
                    fw.version       AS fw_version_ver,
                    fw.nvd_product   AS fw_nvd_product,
                    a.bios_version_id,
                    bv.os_nom        AS bios_version_nom,
                    bv.version       AS bios_version_ver,
                    bv.nvd_product   AS bios_nvd_product,
                    a.numero_serie,
                    a.adresse_ip,
                    a.adresse_mac,
                    a.hostname,
                    a.systeme_exploitation,
                    a.version_os,
                    a.version_firmware,
                    a.version_bios,
                    a.date_installation,
                    a.date_fin_garantie,
                    a.niveau_criticite,
                    a.statut_operationnel,
                    a.proprietes_specifiques,
                    a.notes,
                    a.date_creation,
                    a.date_modification,
                    a.site_id,
                    s.nom            AS site_nom,
                    c.id             AS client_id,
                    c.nom            AS client_nom
                FROM assets a
                JOIN sites s        ON a.site_id   = s.id
                JOIN clients c      ON s.client_id = c.id
                LEFT JOIN product_vendors v  ON a.vendor_id      = v.id
                LEFT JOIN product_models m   ON a.model_id       = m.id
                LEFT JOIN os_versions ov         ON a.os_version_id   = ov.id
                LEFT JOIN os_versions fw         ON a.fw_version_id   = fw.id
                LEFT JOIN os_versions bv         ON a.bios_version_id = bv.id
                LEFT JOIN equipment_types et     ON a.equipment_type_id = et.id
                {where_sql}
                ORDER BY c.nom ASC, s.nom ASC, a.nom_interne ASC
                {limit_sql}
            """
            cursor.execute(query, params)
            return cursor.fetchall()
    except Exception as e:
        print(f"ERREUR SQL list_assets: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ── GET /{id} ──────────────────────────────────────────────────────

@router.get("/{asset_id}")
def get_asset(asset_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT
                    a.*,
                    v.nom          AS vendor_nom,
                    m.nom          AS model_nom,
                    ov.os_nom      AS os_version_nom,
                    ov.version     AS os_version_ver,
                    ov.nvd_product AS os_nvd_product,
                    fw.os_nom      AS fw_version_nom,
                    fw.version     AS fw_version_ver,
                    fw.nvd_product AS fw_nvd_product,
                    bv.os_nom      AS bios_version_nom,
                    bv.version     AS bios_version_ver,
                    bv.nvd_product AS bios_nvd_product,
                    s.nom          AS site_nom,
                    c.id           AS client_id,
                    c.nom          AS client_nom,
                    et.code        AS type_equipement_code,
                    et.label       AS type_equipement_label
                FROM assets a
                JOIN sites s              ON a.site_id         = s.id
                JOIN clients c            ON s.client_id       = c.id
                LEFT JOIN product_vendors v   ON a.vendor_id       = v.id
                LEFT JOIN product_models m    ON a.model_id        = m.id
                LEFT JOIN os_versions ov      ON a.os_version_id   = ov.id
                LEFT JOIN os_versions fw      ON a.fw_version_id   = fw.id
                LEFT JOIN os_versions bv      ON a.bios_version_id = bv.id
                LEFT JOIN equipment_types et  ON a.equipment_type_id = et.id
                WHERE a.id = %s
            """, (asset_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Asset non trouvé")
            return row
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERREUR SQL get_asset: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ── POST / ─────────────────────────────────────────────────────────

@router.post("/", status_code=201)
def create_asset(asset: AssetCreate):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM sites WHERE id = %s", (asset.site_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Site non trouvé")

            cursor.execute("""
                INSERT INTO assets (
                    site_id, nom_interne, type_equipement, equipment_type_id,
                    vendor_id, model_id,
                    os_version_id, fw_version_id, bios_version_id,
                    numero_serie, adresse_ip, adresse_mac, hostname,
                    systeme_exploitation, version_os, version_firmware, version_bios,
                    date_installation, date_fin_garantie,
                    niveau_criticite, statut_operationnel,
                    proprietes_specifiques, notes
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
            """, (
                asset.site_id, asset.nom_interne, asset.type_equipement, asset.equipment_type_id,
                asset.vendor_id, asset.model_id,
                asset.os_version_id, asset.fw_version_id, asset.bios_version_id,
                asset.numero_serie, asset.adresse_ip, asset.adresse_mac, asset.hostname,
                asset.systeme_exploitation, asset.version_os, asset.version_firmware, asset.version_bios,
                asset.date_installation, asset.date_fin_garantie,
                asset.niveau_criticite, asset.statut_operationnel,
                asset.proprietes_specifiques, asset.notes
            ))
            conn.commit()
            new_id = cursor.lastrowid
            return {"message": "Asset créé", "id": new_id}
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERREUR SQL create_asset: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ── PUT /{id} ──────────────────────────────────────────────────────

@router.put("/{asset_id}")
def update_asset(asset_id: int, asset: AssetUpdate):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM assets WHERE id = %s", (asset_id,))
            existing = cursor.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Asset non trouvé")

            cursor.execute("""
                UPDATE assets SET
                    site_id                = %s,
                    nom_interne            = %s,
                    type_equipement        = %s,
                    equipment_type_id      = %s,
                    vendor_id              = %s,
                    model_id               = %s,
                    os_version_id          = %s,
                    fw_version_id          = %s,
                    bios_version_id        = %s,
                    numero_serie           = %s,
                    adresse_ip             = %s,
                    adresse_mac            = %s,
                    hostname               = %s,
                    systeme_exploitation   = %s,
                    version_os             = %s,
                    version_firmware       = %s,
                    version_bios           = %s,
                    date_installation      = %s,
                    date_fin_garantie      = %s,
                    niveau_criticite       = %s,
                    statut_operationnel    = %s,
                    proprietes_specifiques = %s,
                    notes                  = %s
                WHERE id = %s
            """, (
                asset.site_id              if asset.site_id              is not None else existing["site_id"],
                asset.nom_interne          if asset.nom_interne          is not None else existing["nom_interne"],
                asset.type_equipement      if asset.type_equipement      is not None else existing["type_equipement"],
                asset.equipment_type_id    if asset.equipment_type_id    is not None else existing["equipment_type_id"],
                asset.vendor_id            if asset.vendor_id            is not None else existing["vendor_id"],
                asset.model_id             if asset.model_id             is not None else existing["model_id"],
                asset.os_version_id        if asset.os_version_id        is not None else existing["os_version_id"],
                asset.fw_version_id        if asset.fw_version_id        is not None else existing["fw_version_id"],
                asset.bios_version_id      if asset.bios_version_id      is not None else existing["bios_version_id"],
                asset.numero_serie         if asset.numero_serie         is not None else existing["numero_serie"],
                asset.adresse_ip           if asset.adresse_ip           is not None else existing["adresse_ip"],
                asset.adresse_mac          if asset.adresse_mac          is not None else existing["adresse_mac"],
                asset.hostname             if asset.hostname             is not None else existing["hostname"],
                asset.systeme_exploitation if asset.systeme_exploitation is not None else existing["systeme_exploitation"],
                asset.version_os           if asset.version_os           is not None else existing["version_os"],
                asset.version_firmware     if asset.version_firmware     is not None else existing["version_firmware"],
                asset.version_bios         if asset.version_bios         is not None else existing["version_bios"],
                asset.date_installation    if asset.date_installation    is not None else existing["date_installation"],
                asset.date_fin_garantie    if asset.date_fin_garantie    is not None else existing["date_fin_garantie"],
                asset.niveau_criticite     if asset.niveau_criticite     is not None else existing["niveau_criticite"],
                asset.statut_operationnel  if asset.statut_operationnel  is not None else existing["statut_operationnel"],
                asset.proprietes_specifiques if asset.proprietes_specifiques is not None else existing["proprietes_specifiques"],
                asset.notes                if asset.notes                is not None else existing["notes"],
                asset_id
            ))
            conn.commit()
            return {"message": "Asset mis à jour avec succès"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERREUR SQL update_asset: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ── DELETE /{id} ───────────────────────────────────────────────────

@router.delete("/{asset_id}")
def delete_asset(asset_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM assets WHERE id = %s", (asset_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Asset non trouvé")
            cursor.execute("DELETE FROM assets WHERE id = %s", (asset_id,))
            conn.commit()
            return {"message": "Asset supprimé avec succès"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERREUR SQL delete_asset: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()
