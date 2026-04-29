from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel
from typing import Optional
from database import get_connection

router = APIRouter(tags=["Types d'équipements"])


class EquipmentTypeCreate(BaseModel):
    code: str
    label: str
    use_os_version: int = 0
    use_version_os: int = 0
    use_version_firmware: int = 0
    use_version_bios: int = 0
    vendor_source: str = 'materiel'
    notes: Optional[str] = None


class EquipmentTypeUpdate(BaseModel):
    label: Optional[str] = None
    use_os_version: Optional[int] = None
    use_version_os: Optional[int] = None
    use_version_firmware: Optional[int] = None
    use_version_bios: Optional[int] = None
    vendor_source: Optional[str] = None
    notes: Optional[str] = None


@router.get("/api/equipment-types")
def list_equipment_types():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT et.*, COUNT(a.id) AS asset_count
                FROM equipment_types et
                LEFT JOIN assets a ON a.equipment_type_id = et.id
                GROUP BY et.id
                ORDER BY et.label ASC
            """)
            return cur.fetchall()
    finally:
        conn.close()


@router.post("/api/equipment-types", status_code=201)
def create_equipment_type(data: EquipmentTypeCreate):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO equipment_types
                    (code, label, use_os_version, use_version_os,
                     use_version_firmware, use_version_bios, vendor_source, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (data.code, data.label, data.use_os_version, data.use_version_os,
                  data.use_version_firmware, data.use_version_bios,
                  data.vendor_source, data.notes))
            conn.commit()
            new_id = cur.lastrowid
            cur.execute("SELECT * FROM equipment_types WHERE id = %s", (new_id,))
            return cur.fetchone()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()


@router.put("/api/equipment-types/{type_id}")
def update_equipment_type(type_id: int, data: EquipmentTypeUpdate):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM equipment_types WHERE id = %s", (type_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Type introuvable")
            fields = {k: v for k, v in data.dict().items() if v is not None}
            if not fields:
                cur.execute("SELECT * FROM equipment_types WHERE id = %s", (type_id,))
                return cur.fetchone()
            set_clause = ", ".join(f"{k} = %s" for k in fields)
            cur.execute(
                f"UPDATE equipment_types SET {set_clause} WHERE id = %s",
                list(fields.values()) + [type_id]
            )
            conn.commit()
            cur.execute("SELECT * FROM equipment_types WHERE id = %s", (type_id,))
            return cur.fetchone()
    finally:
        conn.close()


@router.delete("/api/equipment-types/{type_id}")
def delete_equipment_type(type_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS nb FROM assets WHERE equipment_type_id = %s",
                (type_id,)
            )
            nb = cur.fetchone()["nb"]
            if nb > 0:
                raise HTTPException(
                    status_code=400,
                    detail=f"Impossible — {nb} asset(s) utilisent ce type"
                )
            cur.execute("DELETE FROM equipment_types WHERE id = %s", (type_id,))
            conn.commit()
            return {"message": "Type supprimé"}
    finally:
        conn.close()
