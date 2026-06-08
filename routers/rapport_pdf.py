"""
routers/rapport_pdf.py
POST /api/rapport/generer  → génère un PDF dans /documents et retourne le nom du fichier
GET  /api/rapport/preview  → retourne les données JSON qui iront dans le PDF (pour preview)
"""

import io
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from database import get_connection

try:
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    )
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

router = APIRouter(prefix="/api/rapport", tags=["Rapport PDF"])

DOCUMENTS_DIR = Path(__file__).resolve().parent.parent / "documents"
DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)

# ── Modèle de requête ──────────────────────────────────────────────────

class RapportRequest(BaseModel):
    # Filtres (mêmes que la page vulns)
    client_id: Optional[int] = None
    site_id: Optional[int] = None
    equipment_type_id: Optional[int] = None
    vendor_id: Optional[int] = None
    model_id: Optional[int] = None
    os_nom: Optional[str] = None
    version_os: Optional[str] = None
    firmware: Optional[str] = None
    asset_nom: Optional[str] = None
    cve_id: Optional[str] = None
    statut: Optional[List[str]] = None
    priorite: Optional[List[str]] = None
    # Champs à inclure dans le PDF
    champs: Optional[List[str]] = None
    # Nom personnalisé du fichier de sortie
    filename: Optional[str] = None
    view_type: Optional[str] = "full"

CHAMPS_DISPONIBLES = [
    "localisation",
    "asset_nom",
    "fabricant_modele",
    "cve_id",
    "description",
    "score_cvss",
    "date_detection",
    "statut",
    "risque_reel",
    "analyse_ia",
]

CHAMPS_LABELS = {
    "localisation":    "Localisation",
    "asset_nom":       "Asset",
    "fabricant_modele":"Fabricant / Modèle",
    "cve_id":          "CVE",
    "description":     "Description",
    "score_cvss":      "Score CVSS",
    "date_detection":  "Détecté le",
    "statut":          "Statut",
    "risque_reel":     "Risque réel",
    "analyse_ia":      "Analyse IA",
}

# ── Requête BDD ────────────────────────────────────────────────────────

def _fetch_correlations(req: RapportRequest):
    conn = get_connection()
    try:
        conditions = ["1=1"]
        params = []

        if req.client_id:
            conditions.append("cl.id = %s"); params.append(req.client_id)
        if req.site_id:
            conditions.append("s.id = %s"); params.append(req.site_id)
        if req.equipment_type_id:
            conditions.append("a.equipment_type_id = %s"); params.append(req.equipment_type_id)
        if req.vendor_id:
            conditions.append("pv.id = %s"); params.append(req.vendor_id)
        if req.model_id:
            conditions.append("pm.id = %s"); params.append(req.model_id)
        if req.os_nom:
            conditions.append("a.systeme_exploitation LIKE %s"); params.append(f"%{req.os_nom}%")
        if req.version_os:
            conditions.append("a.version_os LIKE %s"); params.append(f"%{req.version_os}%")
        if req.asset_nom:
            conditions.append("a.nom_interne LIKE %s"); params.append(f"%{req.asset_nom}%")
        if req.cve_id:
            conditions.append("co.cve_id LIKE %s"); params.append(f"%{req.cve_id}%")
        if req.statut:
            placeholders = ",".join(["%s"] * len(req.statut))
            conditions.append(f"co.statut IN ({placeholders})")
            params.extend(req.statut)
        if req.priorite:
            placeholders = ",".join(["%s"] * len(req.priorite))
            conditions.append(f"co.priorite IN ({placeholders})")
            params.extend(req.priorite)

        where = " AND ".join(conditions)

        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT
                    cl.nom              AS client_nom,
                    s.nom               AS site_nom,
                    a.nom_interne       AS asset_nom,
                    a.type_equipement,
                    pv.nom              AS fabricant_nom,
                    pm.nom              AS modele_nom,
                    a.version_os,
                    co.cve_id,
                    cv.description,
                    cv.cvss_v3_score,
                    cv.cvss_v3_severity,
                    co.statut,
                    co.priorite,
                    co.score_contextuel,
                    co.date_detection,
                    co.risque_reel,
                    co.analyse_mistral
                FROM correlations co
                JOIN assets a        ON a.id         = co.asset_id
                JOIN cve cv          ON cv.cve_id    = co.cve_id
                JOIN product_vendors pv ON pv.id     = a.vendor_id
                LEFT JOIN product_models pm ON pm.id = a.model_id
                JOIN sites s         ON s.id          = a.site_id
                JOIN clients cl      ON cl.id         = s.client_id
                WHERE {where}
                ORDER BY cl.nom, s.nom, co.priorite, co.cve_id
            """, params)
            return cur.fetchall()
    finally:
        conn.close()

# ── Preview JSON ───────────────────────────────────────────────────────

@router.post("/preview")
def preview_rapport(req: RapportRequest):
    rows = _fetch_correlations(req)
    return {"total": len(rows), "rows": rows[:5]}

# ── Génération PDF ─────────────────────────────────────────────────────

PRIORITY_COLORS_MAP = {
    "critique": colors.HexColor("#C0392B") if REPORTLAB_OK else None,
    "haute":    colors.HexColor("#E67E22") if REPORTLAB_OK else None,
    "moyenne":  colors.HexColor("#D4AC0D") if REPORTLAB_OK else None,
    "basse":    colors.HexColor("#1E8449") if REPORTLAB_OK else None,
}

STATUT_LABELS = {
    "nouveau": "Nouveau", "en_analyse": "En analyse", "confirme": "Confirmé",
    "mitige": "Mitigé", "faux_positif": "Faux positif", "patche": "Patché",
}

def _build_pdf(rows, champs: List[str], filename: str, req: RapportRequest):
    output_path = DOCUMENTS_DIR / filename
    view_type = req.view_type or "full"
    PAGE = A4 if view_type == "treeview" else landscape(A4)  # <-- Modification ici
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=PAGE,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
    )

    styles = getSampleStyleSheet()
    style_normal = ParagraphStyle("N", parent=styles["Normal"], fontSize=7, leading=9)
    style_small = ParagraphStyle("S", parent=styles["Normal"], fontSize=6.5, leading=8,
                                  textColor=colors.HexColor("#555555"))
    style_bold = ParagraphStyle("B", parent=styles["Normal"], fontSize=7.5,
                                fontName="Helvetica-Bold", leading=9)
    style_h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=16,
                              textColor=colors.HexColor("#1A252F"), spaceAfter=2)
    style_h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=10,
                              textColor=colors.HexColor("#1E3A5F"), spaceBefore=10, spaceAfter=4,
                              fontName="Helvetica-Bold")
    style_h3 = ParagraphStyle("H3", parent=styles["Normal"], fontSize=9,
                              textColor=colors.HexColor("#1E3A5F"), spaceBefore=6, spaceAfter=2,
                              fontName="Helvetica-Bold")
    style_meta = ParagraphStyle("M", parent=styles["Normal"], fontSize=8,
                                textColor=colors.HexColor("#666666"), spaceAfter=8)
    style_italic = ParagraphStyle("I", parent=styles["Normal"], fontSize=6.5,
                                  textColor=colors.HexColor("#444444"), leading=8)

    elements = []

    # En-tête général
    elements.append(Paragraph("Rapport de Vulnérabilités CVE", style_h1))
    view_type_label = "Résumé (Treeview)" if (req.view_type or "full") == "treeview" else "Rapport complet"
    filtres_desc = f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} · {len(rows)} vulnérabilité(s) · {view_type_label}"
    if req.statut:
        filtres_desc += f" · Statuts : {', '.join(req.statut)}"
    if req.priorite:
        filtres_desc += f" · Priorités : {', '.join(req.priorite)}"
    elements.append(Paragraph(filtres_desc, style_meta))
    elements.append(Spacer(1, 0.3*cm))

    # --- Gestion des deux types de vue ---
    view_type = req.view_type or "full"

    if view_type == "treeview":
        # ============================================
        # VUE TREEVIEW (hiérarchique améliorée)
        # ============================================
        # Définir les emojis et couleurs par niveau
        client_emoji = "🏢"
        site_emoji = "📍"
        asset_emoji = "💻"

        # Couleurs pour les niveaux
        client_color = colors.HexColor("#58A6FF")
        site_color = colors.HexColor("#8B949E")
        asset_color = colors.HexColor("#F85149")

        # Style pour les emojis (taille légèrement plus grande)
        style_emoji = ParagraphStyle(
            "emoji",
            parent=styles["Normal"],
            fontSize=9,
            leading=10,
        )

        # Grouper par client → site → asset
        tree = {}
        for row in rows:
            client = row.get('client_nom', 'Inconnu')
            site = row.get('site_nom', 'Inconnu')
            asset = row.get('asset_nom', 'Inconnu')

            if client not in tree:
                tree[client] = {}
            if site not in tree[client]:
                tree[client][site] = {}
            if asset not in tree[client][site]:
                tree[client][site][asset] = 0
            tree[client][site][asset] += 1

        # Construire le PDF en mode treeview
        for client, sites in tree.items():
            # Ligne horizontale pour séparer les clients
            elements.append(Paragraph(f"{client_emoji} <b>{client}</b>", style_h2))
            elements.append(Spacer(1, 0.1 * cm))

            for site, assets in sites.items():
                # Indentation + emoji + couleur pour les sites
                site_paragraph = Paragraph(
                    f"  {site_emoji} <b>{site}</b>",
                    ParagraphStyle(
                        "site_style",
                        parent=style_normal,
                        textColor=site_color,
                        fontSize=8,
                        leading=10,
                        leftIndent=20,
                    )
                )
                elements.append(site_paragraph)
                elements.append(Spacer(1, 0.05 * cm))

                for asset_name, vuln_count in assets.items():
                    # Indentation + emoji + couleur pour les assets
                    asset_text = f"    {asset_emoji} {asset_name} ({vuln_count} vulnérabilité{'s' if vuln_count > 1 else ''})"
                    asset_paragraph = Paragraph(
                        asset_text,
                        ParagraphStyle(
                            "asset_style",
                            parent=style_normal,
                            textColor=asset_color,
                            fontSize=7.5,
                            leading=9,
                            leftIndent=40,
                        )
                    )
                    elements.append(asset_paragraph)

            # Espace entre les sites
            elements.append(Spacer(1, 0.1 * cm))

        # Espace entre les clients
        elements.append(Spacer(1, 0.2 * cm))

    else:
        # ============================================
        # VUE COMPLÈTE (tableau détaillé)
        # ============================================
        # Construire les colonnes selon les champs sélectionnés
        LARGEURS_REL = {
            "localisation":     7,
            "asset_nom":        10,
            "fabricant_modele": 10,
            "cve_id":           10,
            "description":      14,
            "score_cvss":       5,
            "date_detection":   6,
            "statut":           6,
            "risque_reel":      10,
            "analyse_ia":       14,
        }

        page_width = landscape(A4)[0] - 3*cm
        total_parts = sum(LARGEURS_REL[ch] for ch in champs if ch in LARGEURS_REL)

        col_defs = []
        for ch in champs:
            if ch == "localisation":
                label = "Localisation"
            elif ch == "asset_nom":
                label = "Asset"
            elif ch == "fabricant_modele":
                label = "Fabricant/Modèle"
            elif ch == "cve_id":
                label = "CVE"
            elif ch == "description":
                label = "Description"
            elif ch == "score_cvss":
                label = "Score"
            elif ch == "date_detection":
                label = "Détecté le"
            elif ch == "statut":
                label = "Statut"
            elif ch == "risque_reel":
                label = "Risque réel"
            elif ch == "analyse_ia":
                label = "Analyse IA"
            else:
                continue
            part = LARGEURS_REL.get(ch, 8)
            width = (part / total_parts) * page_width
            col_defs.append((ch, label, width))

        col_keys = [c[0] for c in col_defs]
        col_headers = [c[1] for c in col_defs]
        col_widths = [c[2] for c in col_defs]

        def fmt_date(d):
            if not d: return "N/A"
            try:
                dt = datetime.fromisoformat(str(d))
                return dt.strftime("%d/%m/%Y\n%H:%M")
            except Exception:
                return str(d)[:10]

        def fmt_analyse(text):
            if not text: return ""
            text = str(text)
            for prefix in ["[Verdict Mistral:", "[Ajustement:"]:
                if prefix in text:
                    idx = text.find("]", text.find(prefix))
                    if idx != -1:
                        text = text[idx+1:].strip()
            return text[:300]

        def cell(key, row):
            if key == "localisation":
                return Paragraph(f"{row.get('client_nom','')}\n{row.get('site_nom','')}", style_normal)
            elif key == "asset_nom":
                return Paragraph(f"<b>{row.get('asset_nom','')}</b>\n<font size='6'>{row.get('type_equipement','')}</font>", style_normal)
            elif key == "fabricant_modele":
                fab = row.get('fabricant_nom','N/A')
                mod = row.get('modele_nom','') or row.get('version_os','') or ''
                return Paragraph(f"{fab}\n<font size='6'>{mod}</font>", style_normal)
            elif key == "cve_id":
                cve = row.get('cve_id') or ''
                style_cve = ParagraphStyle("cve", parent=style_normal,
                    textColor=colors.HexColor("#1e40af"),
                    fontSize=6.5, leading=8,
                    splitLongWords=True,
                    wordWrap='LTR')
                return Paragraph(cve, style_cve)
            elif key == "description":
                desc = (row.get('description') or '')[:200]
                return Paragraph(desc, style_small)
            elif key == "score_cvss":
                score = row.get('cvss_v3_score','')
                sev = (row.get('cvss_v3_severity','') or '').replace('CRITICAL','CRIT.').replace('MEDIUM','MED.')
                color = "#C0392B" if float(score or 0) >= 9 else "#E67E22" if float(score or 0) >= 7 else "#555"
                return Paragraph(f"<font color='{color}'><b>{score}</b></font><br/><font size='6'>{sev}</font>", style_normal)
            elif key == "date_detection":
                return Paragraph(fmt_date(row.get('date_detection')), style_small)
            elif key == "statut":
                s = row.get('statut','')
                p = row.get('priorite','')
                return Paragraph(f"{STATUT_LABELS.get(s,s)}\n<font size='6'>{p.upper() if p else ''}</font>", style_normal)
            elif key == "risque_reel":
                return Paragraph((row.get('risque_reel') or 'N/A')[:150], style_small)
            elif key == "analyse_ia":
                return Paragraph(fmt_analyse(row.get('analyse_mistral')), style_italic)
            return Paragraph("", style_normal)

        # Grouper par (client, site)
        groupes = {}
        for row in rows:
            key = (row.get('client_nom',''), row.get('site_nom',''))
            groupes.setdefault(key, []).append(row)

        header_style = TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), colors.HexColor("#E8EEF5")),
            ("TEXTCOLOR",    (0,0), (-1,0), colors.HexColor("#374151")),
            ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,0), 7),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F9FAFB")]),
            ("FONTSIZE",     (0,1), (-1,-1), 7),
            ("VALIGN",       (0,0), (-1,-1), "TOP"),
            ("GRID",         (0,0), (-1,-1), 0.3, colors.HexColor("#E2E8F0")),
            ("TOPPADDING",   (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ("LEFTPADDING",  (0,0), (-1,-1), 5),
            ("RIGHTPADDING", (0,0), (-1,-1), 5),
        ])

        first_group = True
        for (client_nom, site_nom), group_rows in groupes.items():
            if not first_group:
                elements.append(PageBreak())
            first_group = False

            # En-tête de section
            elements.append(Paragraph(
                f"{client_nom} — {site_nom}  ·  {len(group_rows)} vulnérabilité(s)",
                style_h2
            ))
            elements.append(Spacer(1, 0.2*cm))

            # Tableau
            table_data = [[Paragraph(h, ParagraphStyle("TH", parent=styles["Normal"],
                            fontSize=7, fontName="Helvetica-Bold")) for h in col_headers]]
            for row in group_rows:
                table_data.append([cell(k, row) for k in col_keys])

            t = Table(table_data, colWidths=col_widths, repeatRows=1)
            t.setStyle(header_style)
            elements.append(t)

    doc.build(elements)
    return output_path

@router.post("/generer")
def generer_rapport(req: RapportRequest):
    if not REPORTLAB_OK:
        raise HTTPException(status_code=500, detail="ReportLab non installé. Lancer : pip install reportlab")

    champs = req.champs or CHAMPS_DISPONIBLES
    rows = _fetch_correlations(req)

    if not rows:
        raise HTTPException(status_code=404, detail="Aucune vulnérabilité trouvée avec ces filtres.")

    def _sanitize_filename(name: str) -> str:
        import re
        name = name.strip()
        if not name.endswith('.pdf'):
            name += '.pdf'
        name = re.sub(r'[/\\<>:"|?*\s]', '_', name)
        if len(name) > 200:
            name = name[:196] + '.pdf'
        return name

    ts = datetime.now().strftime("%Y_%m_%d_%H_%M")
    if req.filename and req.filename.strip():
        filename = _sanitize_filename(req.filename)
    else:
        filename = f"rapport_vuln_{ts}.pdf"

    _build_pdf(rows, champs, filename, req)

    return {
        "filename": filename,
        "total": len(rows),
        "url": f"/api/documents/{filename}",
    }