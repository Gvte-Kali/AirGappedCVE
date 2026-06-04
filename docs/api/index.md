---
title: API FastAPI
nav_order: 6
has_children: true
---

# 🔌 API FastAPI

**Référence de l'API REST** - Documentation interactive disponible sur `/docs` (Swagger UI).

---

## 📚 **Documentation interactive**

- **Swagger UI** : `/docs` - Interface web complète avec test des endpoints
- **ReDoc** : `/redoc` - Documentation alternative
- **OpenAPI JSON** : `/openapi.json` - Schéma OpenAPI

---

## 🎯 **Base URL**

```
http://IP_DU_SERVEUR:3000
```

---

## 📋 **Endpoints principaux**

### Clients

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/clients` | Lister tous les clients |
| GET | `/api/clients/{id}` | Récupérer un client |
| POST | `/api/clients` | Créer un client |
| PUT | `/api/clients/{id}` | Mettre à jour un client |
| DELETE | `/api/clients/{id}` | Supprimer un client |

### Sites

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/sites` | Lister tous les sites |
| GET | `/api/sites/{id}` | Récupérer un site |
| POST | `/api/sites` | Créer un site |
| PUT | `/api/sites/{id}` | Mettre à jour un site |
| DELETE | `/api/sites/{id}` | Supprimer un site |

### Assets

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/assets` | Lister tous les assets |
| GET | `/api/assets/{id}` | Récupérer un asset |
| POST | `/api/assets` | Créer un asset |
| PUT | `/api/assets/{id}` | Mettre à jour un asset |
| DELETE | `/api/assets/{id}` | Supprimer un asset |

### Corrélations

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/correlations` | Lister toutes les corrélations |
| GET | `/api/correlations/{id}` | Récupérer une corrélation |
| GET | `/api/correlations/asset/{asset_id}` | Corrélations d'un asset |
| POST | `/api/correlations/run` | Lancer la corrélation |
| POST | `/api/correlations/analyze` | Lancer l'analyse Mistral |
| GET | `/api/correlations/run-status` | Statut de l'exécution |
| GET | `/api/correlations/export` | Exporter les corrélations |

### Fabricants

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/vendors` | Lister tous les fabricants |
| POST | `/api/vendors` | Créer un fabricant |
| PUT | `/api/vendors/{id}` | Mettre à jour un fabricant |
| DELETE | `/api/vendors/{id}` | Supprimer un fabricant |

### Modèles

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/models` | Lister tous les modèles |
| POST | `/api/models` | Créer un modèle |
| PUT | `/api/models/{id}` | Mettre à jour un modèle |
| DELETE | `/api/models/{id}` | Supprimer un modèle |

### OS & Versions

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/os-versions` | Lister toutes les versions |
| POST | `/api/os-versions` | Créer une version |
| PUT | `/api/os-versions/{id}` | Mettre à jour une version |
| DELETE | `/api/os-versions/{id}` | Supprimer une version |

### Types d'équipements

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/equipment-types` | Lister tous les types |
| POST | `/api/equipment-types` | Créer un type |
| PUT | `/api/equipment-types/{id}` | Mettre à jour un type |
| DELETE | `/api/equipment-types/{id}` | Supprimer un type |

---

## 🔐 **Authentification**

**Actuellement** : Pas d'authentification (accès local uniquement).

**Recommandation pour la production** :
- Utiliser un reverse proxy (Nginx, Apache) avec authentification
- Limiter l'accès par IP (firewall)
- Activer HTTPS

---

## 📝 **Pagination**

Les endpoints de liste supportent la pagination :

```
GET /api/assets?page=1&per_page=50
```

**Paramètres** :
- `page` : Numéro de page (défaut: 1)
- `per_page` : Nombre d'éléments par page (défaut: 50, max: 1000)

---

## 🔍 **Filtres**

La plupart des endpoints de liste supportent des filtres :

```
GET /api/assets?client_id=1&site_id=2&vendor_id=3
GET /api/correlations?statut=confirme&priorite=critique
```

---

## 📤 **Réponses**

### Format de réponse

```json
{
  "success": true,
  "data": {...},
  "message": "Opération réussie"
}
```

### Codes HTTP

| Code | Description |
|------|-------------|
| 200 | Succès |
| 201 | Créé |
| 400 | Requête invalide |
| 404 | Non trouvé |
| 409 | Conflit (exécution en cours) |
| 500 | Erreur serveur |

---

## 💡 **Exemples**

### Créer un client

```bash
curl -X POST http://localhost:3000/api/clients \
  -H "Content-Type: application/json" \
  -d '{"nom": "Mon Client", "contact_nom": "Jean Dupont", "contact_email": "jean@client.com"}'
```

### Lister les assets d'un client

```bash
curl -X GET http://localhost:3000/api/assets?client_id=1
```

### Lancer une corrélation

```bash
curl -X POST http://localhost:3000/api/correlations/run
```

### Voir le statut de l'exécution

```bash
curl -X GET http://localhost:3000/api/correlations/run-status
```
