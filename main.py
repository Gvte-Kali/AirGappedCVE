# =============================================================================
# main.py — Point d'entrée principal de l'application FastAPI
# Auteur : KaliGvte
# Description :
#   - Initialise l'application FastAPI pour AirGappedCVE
#   - Enregistre tous les routers API (clients, sites, assets, CVE, etc.)
#   - Gère les routes des pages UI statiques (HTML)
#   - Monte les fichiers statiques (CSS, JS, images)
#   - Configuration : redirect_slashes=False pour éviter les redirections automatiques
# =============================================================================

# --- Imports des dépendances FastAPI ---
from routers.scripts import router as scripts_router
from routers import clients, sites, assets, vendors, models, documents, correlations, os_versions, equipment_types, import_assets, parametres_correlation, rapport_pdf
from routers.cve import router as cve_router  # Router pour la gestion des CVE (GET /api/cve)
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles  # Pour servir les fichiers statiques (CSS, JS, images)
from fastapi.responses import FileResponse  # Pour retourner des fichiers HTML
from dotenv import load_dotenv  # Charge les variables d'environnement depuis .env

# --- Chargement de la configuration ---
# Charge les variables d'environnement (DB_HOST, DB_USER, DB_PASSWORD, etc.) depuis le fichier .env
load_dotenv()

# =============================================================================
# INSTANCIATION DE L'APPLICATION FASTAPI
# =============================================================================
# redirect_slashes=False : Désactive la redirection automatique des URLs avec / final
# Exemple : /api/assets et /api/assets/ sont considérés comme des routes différentes
app = FastAPI(
    title="Asset & Vulnerability Manager",  # Titre affiché dans la documentation Swagger/OpenAPI
    description="Système de gestion d'assets informatiques et de vulnérabilités pour environnements air-gapped",
    version="1.0.0",
    redirect_slashes=False,
)

# =============================================================================
# ENREGISTREMENT DES ROUTERS API
# Chaque router est associé à un préfixe d'URL et des tags pour la documentation Swagger
# =============================================================================

# --- Routers principaux (ressources métiers) ---
# Clients : Gestion des clients (CRUD)
app.include_router(clients.router,
                   prefix="/api/clients",      # URL de base : /api/clients
                   tags=["Clients"])            # Tag pour regrouper dans Swagger

# Sites : Gestion des sites (CRUD)
app.include_router(sites.router,
                   prefix="/api/sites",        # URL de base : /api/sites
                   tags=["Sites"])

# Assets : Gestion des assets (CRUD + filtres)
app.include_router(
    assets.router,       # Router défini dans routers/assets.py
    prefix="/api/assets",       # URL de base : /api/assets
    tags=["Assets"]
)

# Corrélations : Gestion des corrélations CVE/assets
app.include_router(correlations.router,
                   prefix="/api/correlations",  # URL de base : /api/correlations
                   tags=["Vulnérabilités"])

# --- Routers de référentiels ---
# Vendors : Gestion des fabricants (CRUD)
app.include_router(vendors.router,
                   prefix="/api")  # URL de base : /api/vendors (défini dans le router)

# Models : Gestion des modèles (CRUD)
app.include_router(models.router,
                   prefix="/api")  # URL de base : /api/models (défini dans le router)

# OS Versions : Gestion des OS et versions normalisées
app.include_router(os_versions.router,
                   tags=["OS Versions"])  # Pas de préfixe : utilise celui défini dans le router

# Equipment Types : Gestion des types d'équipements
app.include_router(equipment_types.router)  # Pas de préfixe : utilise celui défini dans le router

# Paramètres de corrélation : Configuration des règles de corrélation CVE
app.include_router(parametres_correlation.router)  # Pas de préfixe : utilise celui défini dans le router

# Rapports PDF : Génération de rapports
app.include_router(rapport_pdf.router)  # Pas de préfixe : utilise celui défini dans le router

# --- Router CVE (NOUVEAU) ---
# Gestion des vulnérabilités CVE (liste, filtres par fabricant/type)
app.include_router(
    cve_router,                  # Router défini dans routers/cve.py,
    tags=["CVE"]
)

# --- Routers utilitaires ---
# Scripts : Exécution des scripts système (corrélation, analyse, etc.)
app.include_router(scripts_router)  # Pas de préfixe : utilise celui défini dans le router

# Import Assets : Import d'assets depuis un fichier Excel
app.include_router(import_assets.router)  # Pas de préfixe : utilise celui défini dans le router

# Documents : Gestion des documents (upload, téléchargement)
app.include_router(documents.router)  # Pas de préfixe : utilise celui défini dans le router

# =============================================================================
# ROUTES DES PAGES UI (INTERFACE WEB)
# Chaque endpoint retourne une page HTML statique depuis le dossier /ui
# =============================================================================

# Page d'accueil
@app.get("/")
def index():
    return FileResponse("ui/index.html")  # Affiche la page d'accueil

# --- Pages Inventaire ---
@app.get("/ui/clients")
def ui_clients():
    return FileResponse("ui/clients.html")  # Gestion des clients

@app.get("/ui/sites")
def ui_sites():
    return FileResponse("ui/sites.html")  # Gestion des sites

@app.get("/ui/assets")
def ui_assets():
    return FileResponse("ui/assets.html")  # Gestion des assets

# --- Pages Référentiels ---
@app.get("/ui/vendors")
def ui_vendors():
    return FileResponse("ui/vendors.html")  # Gestion des fabricants

@app.get("/ui/models")
def ui_models():
    return FileResponse("ui/models.html")  # Gestion des modèles

@app.get("/ui/os-versions")
def ui_os_versions():
    return FileResponse("ui/os_versions.html")  # Gestion des OS et versions

# --- Page Outils ---
@app.get("/ui/vulns")
def ui_vulns():
    return FileResponse("ui/vulns.html")  # Gestion des vulnérabilités (corrélations)

@app.get("/ui/equipment-types")
def ui_equipment_types():
    return FileResponse("ui/equipment-types.html")  # Gestion des types d'équipements

@app.get("/ui/parametres")
def ui_parametres():
    return FileResponse("ui/parametres.html")  # Paramètres de corrélation

@app.get("/ui/import")
def ui_import():
    return FileResponse("ui/import.html")  # Import d'assets depuis Excel

# --- Page CVE (NOUVEAU) ---
@app.get("/ui/cve")
def ui_cve():
    return FileResponse("ui/cve.html")  # Visualisation des CVE avec filtres

# --- Page Documents ---
@app.get("/ui/documents")
def ui_documents():
    return FileResponse("ui/documents.html")  # Gestion des documents (PDF)

# =============================================================================
# ROUTE DE SANTÉ (HEALTH CHECK)
# Utilisée pour vérifier que l'API est opérationnelle (monitoring, Kubernetes, etc.)
# =============================================================================
@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}  # Retourne un statut simple pour les vérifications

# =============================================================================
# FICHIERS STATIQUES (CSS, JS, IMAGES)
# TOUJOURS EN DERNIER : Monte le dossier /ui/static sur /static
# =============================================================================
app.mount(
    "/static",                     # URL de base pour accéder aux fichiers statiques
    StaticFiles(directory="ui/static"),  # Dossier source contenant les fichiers
    name="static"                  # Nom unique pour identifier ce monture
)