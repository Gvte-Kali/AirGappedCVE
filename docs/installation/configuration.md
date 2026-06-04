---
title: Configuration
parent: Installation & Déploiement
nav_order: 3
---

# Configuration

**Fichiers de configuration de l'application**

---

## 🔐 **Fichier `.env`**

**Variables sensibles** - Ne jamais versionner !

```bash
cp .env.example .env
nano .env
```

### Variables principales

```ini
# Base de données
DB_HOST=localhost
DB_PORT=3306
DB_NAME=asset_vuln_manager
DB_USER=votre_utilisateur
DB_PASSWORD=votre_mot_de_passe

# Mistral AI
MISTRAL_API_KEY=votre_cle_api
```

⚠️ **Important** : `.env` est dans `.gitignore` - ne jamais le committer !

---

## ⚙️ **Fichier `scripts/config.yml`**

**Comportement du moteur de corrélation** - Modifiable via l'interface web.

### Paramètres principaux

```yaml
correlation:
  cvss_min: 4.0           # Score CVSS minimum
  cvss_network_min: 7.0  # Score min pour CVE réseau (AV:N)
  date_min: "2015-01-01" # Date minimale des CVE
  vendor_cve_limit: 2000 # Limite CVE par vendor
  dry_run: false          # Mode test (pas d'insertion)
  verbose: true           # Logs détaillés

mistral:
  model: "mistral-large-latest"
  delay_seconds: 15.0     # Délai entre appels API
  max_retries: 3          # Tentatives en cas d'erreur
  batch_max: 0            # 0 = illimité
  max_tokens: 512        # Tokens max par réponse
  force: false            # Réanalyser les corrélations existantes

rapport:
  output_dir: "documents"
  score_min: 0.0
```

### Mapping OS → Vendor NVD

```yaml
os_vendor_map:
  windows: microsoft
  dsm: synology
  fortios: fortinet
  linux: linux
  ubuntu: canonical
  # Ajouter vos mappings ici
```

---

## 📝 **Fichier `scripts/vuln_types.yml`**

Classification des types d'attaques. Voir [Référence]({{ site.baseurl }}/reference/vuln-types).

---

## 🎛️ **Variables optionnelles**

Certaines variables `.env` peuvent surcharger `config.yml` :

| Variable | Surcharge |
|----------|-----------|
| `MISTRAL_MODEL` | `mistral.model` |
| `MISTRAL_DELAY` | `mistral.delay_seconds` |
| `MISTRAL_BATCH_MAX` | `mistral.batch_max` |

**Priorité** : Variable d'environnement > config.yml > valeur par défaut
