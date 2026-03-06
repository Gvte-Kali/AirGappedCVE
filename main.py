from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv

load_dotenv()

from routers import clients, sites, assets, vendors, models, documents
from routers.scripts import router as scripts_router

app = FastAPI(
    title="Asset & Vulnerability Manager",
    description="Système de gestion d'assets informatiques et de vulnérabilités",
    version="1.0.0",
)

# ── Routers API ──
app.include_router(clients.router, prefix="/api/clients", tags=["Clients"])
app.include_router(sites.router,   prefix="/api/sites",   tags=["Sites"])
app.include_router(assets.router,  prefix="/api/assets",  tags=["Assets"])
app.include_router(vendors.router, prefix="/api",          tags=["Fabricants"])
app.include_router(models.router,  prefix="/api",          tags=["Modèles"])

# Router Scripts
app.include_router(scripts_router)

# Router Documents
app.include_router(documents.router)

# ── Pages UI ──
@app.get("/")
def index():
    return FileResponse("ui/index.html")

@app.get("/ui/clients")
def ui_clients():
    return FileResponse("ui/clients.html")

@app.get("/ui/sites")
def ui_sites():
    return FileResponse("ui/sites.html")

@app.get("/ui/assets")
def ui_assets():
    return FileResponse("ui/assets.html")

@app.get("/ui/vendors")
def ui_vendors():
    return FileResponse("ui/vendors.html")

@app.get("/ui/models")
def ui_models():
    return FileResponse("ui/models.html")

@app.get("/ui/documents")
def ui_documents():
    return FileResponse("ui/documents.html")

@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}

# ── Static (TOUJOURS EN DERNIER) ──
app.mount("/static", StaticFiles(directory="ui/static"), name="static")
