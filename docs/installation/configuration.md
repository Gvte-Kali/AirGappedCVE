---
title: Configuration
parent: Installation & Déploiement
nav_order: 3
---

# Configuration
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Fichier `.env`

Le fichier `.env` contient les variables sensibles de l'application. Il ne doit **jamais** être versionné (il est dans le `.gitignore`).

```bash
# Copier le modèle
cp .env.example .env
nano .env
```

### Variables disponibles

```ini
# ── Base de données ──────────────────────────────────────────
DB_HOST=localhost
DB_PORT=3306
DB_NAME=asset_vuln_manager
DB_USER=votre_utilisateur_mariadb
DB_PASSWORD=votre_mot_de_passe_mariadb

# ── Mistral AI ───────────────────────────────────────────────
MISTRAL_API_KEY=votre_cle_api_mistral

# Optionnel : surcharger le modèle défini dans config.yml ( non recommandé )
# MISTRAL_MODEL=mistral-large-latest

```

{: .warning }
Ne jamais committer le fichier `.env`. Vérifier que `.gitignore` contient bien la ligne `.env`.

---

## Fichier `scripts/config.yml`

Le fichier `config.yml` contrôle le comportement du moteur de corrélation. Contrairement au `.env`, il est versionné et peut être modifié selon les besoins.
Ce fichier est maintenant accessible via la page de parametrage de la corrélation dans l'interface Web, inutile de le modifier directement.

```yaml
correlation:
  # Score CVSS minimum pour qu'une CVE soit considérée
  cvss_min: 4.0

  # Score CVSS minimum pour les CVE réseau (AV:N)
  # Les CVE réseau sous ce seuil sont filtrées (moins pertinentes en air-gap)
  cvss_network_min: 7.0

  # Date minimale de publication des CVE
  date_min: "2015-01-01"

  # Nombre max de CVE chargées en cache par vendor (0 = illimité)
  # Augmenter si des CVE manquent pour un vendor avec beaucoup de CVE (ex: microsoft)
  vendor_cve_limit: 2000

  # Mapping OS textuel → vendor NVD
  # Utilisé quand l'asset n'a pas d'OS normalisé (os_version_id NULL)
  os_vendor_map:
    windows: microsoft
    dsm: synology
    fortios: fortinet
    linux: linux
    ubuntu: canonical
    # ... ajouter selon vos équipements

  # Mode dry-run : affiche les corrélations sans les insérer en base
  dry_run: false

  # Verbosité des logs de corrélation
  verbose: true

mistral:
  # Modèle Mistral à utiliser
  model: "mistral-large-latest"

  # Délai entre chaque appel API (secondes)
  # Adapter selon votre quota (clé gratuite ≈ 6 req/min)
  delay_seconds: 15.0

  # Nombre max de tentatives en cas de rate limit
  max_retries: 3

  # Nombre max de corrélations analysées par run (0 = illimité)
  batch_max: 0

  # Nombre max de tokens en sortie par appel Mistral
  max_tokens: 512

  # Forcer la réanalyse des corrélations déjà analysées
  force: false

rapport:
  # Répertoire de sortie des PDFs
  output_dir: "documents"

  # Statuts inclus dans les rapports PDF
  statuts_inclus:
    - "confirme"
    - "informatif"
    - "mitige"

  # Score minimum pour apparaître dans le rapport
  score_min: 0.0
```

Pour la référence complète de chaque paramètre, voir [config.yml — Référence complète]({{ site.baseurl }}/reference/config).

---

## Fichier `scripts/vuln_types.yml`

Ce fichier définit la classification des types d'attaque utilisée lors de la corrélation. Il est chargé au démarrage du moteur.

Voir [vuln_types.yml]({{ site.baseurl }}/reference/vuln-types) pour la documentation complète.

---

## Variables d'environnement optionnelles

Certaines variables du `.env` peuvent surcharger les valeurs de `config.yml` :

| Variable | Surcharge |
|----------|-----------|
| `MISTRAL_MODEL` | `mistral.model` |
| `MISTRAL_DELAY` | `mistral.delay_seconds` |
| `MISTRAL_BATCH_MAX` | `mistral.batch_max` |

La priorité est : **variable d'environnement > config.yml > valeur par défaut du code**.
