"""
API Router pour la gestion des documents PDF
"""
import os
from pathlib import Path
from datetime import datetime
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from typing import List, Dict

router = APIRouter(prefix="/api/documents", tags=["documents"])

DOCUMENTS_DIR = Path(__file__).parent.parent / "documents"

# S'assurer que le répertoire existe
DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)


@router.get("")
async def list_documents() -> Dict[str, List[Dict]]:
    """
    Liste tous les documents PDF disponibles dans le répertoire documents.

    Returns:
        Liste des documents avec leurs métadonnées
    """
    try:
        documents = []

        if not DOCUMENTS_DIR.exists():
            return {"documents": []}

        # Parcourir tous les fichiers PDF
        for file_path in DOCUMENTS_DIR.glob("*.pdf"):
            if file_path.is_file():
                stat = file_path.stat()

                # Déterminer le type de document
                doc_type = "complet"
                if "synthese" in file_path.name.lower():
                    doc_type = "synthese"

                documents.append({
                    "name": file_path.name,
                    "type": doc_type,
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "path": str(file_path)
                })

        # Trier par date de création décroissante
        documents.sort(key=lambda x: x["created"], reverse=True)

        return {"documents": documents}

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Erreur lors de la liste des documents: {str(e)}")


@router.get("/{filename}")
async def download_document(filename: str, preview: bool = False):
    """
    Télécharge ou affiche un document PDF.

    Args:
        filename: Nom du fichier à télécharger
        preview: Si True, affiche le PDF dans le navigateur au lieu de le télécharger

    Returns:
        Le fichier PDF
    """
    try:
        file_path = DOCUMENTS_DIR / filename

        # Vérifier que le fichier existe
        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="Document non trouvé")

        # Vérifier que c'est bien un PDF
        if not filename.lower().endswith('.pdf'):
            raise HTTPException(
                status_code=400, detail="Seuls les fichiers PDF sont autorisés")

        # Vérifier que le fichier est bien dans le répertoire documents (sécurité)
        try:
            file_path.resolve().relative_to(DOCUMENTS_DIR.resolve())
        except ValueError:
            raise HTTPException(status_code=403, detail="Accès interdit")

        # Déterminer le type de média
        media_type = "application/pdf"

        # Headers pour le téléchargement ou l'affichage
        headers = {}
        if not preview:
            headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        else:
            headers["Content-Disposition"] = f'inline; filename="{filename}"'

        return FileResponse(
            path=str(file_path),
            media_type=media_type,
            headers=headers,
            filename=filename
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Erreur lors du téléchargement: {str(e)}")


@router.delete("/{filename}")
async def delete_document(filename: str) -> Dict[str, str]:
    """
    Supprime un document PDF.

    Args:
        filename: Nom du fichier à supprimer

    Returns:
        Message de confirmation
    """
    try:
        file_path = DOCUMENTS_DIR / filename

        # Vérifier que le fichier existe
        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="Document non trouvé")

        # Vérifier que c'est bien un PDF
        if not filename.lower().endswith('.pdf'):
            raise HTTPException(
                status_code=400, detail="Seuls les fichiers PDF peuvent être supprimés")

        # Vérifier que le fichier est bien dans le répertoire documents (sécurité)
        try:
            file_path.resolve().relative_to(DOCUMENTS_DIR.resolve())
        except ValueError:
            raise HTTPException(status_code=403, detail="Accès interdit")

        # Supprimer le fichier
        file_path.unlink()

        return {"message": f"Document '{filename}' supprimé avec succès"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Erreur lors de la suppression: {str(e)}")
