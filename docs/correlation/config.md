---
title: config.yml
parent: Moteur de corrélation
nav_order: 7
---

# ⚙️ Référence config.yml

**Paramètres du moteur de corrélation et de l'analyse Mistral** - Modifiable via l'interface web.

---

## 📊 **Section `correlation`**

### Filtres CVSS

```yaml
correlation:
  cvss_min: 4.0           # Score CVSS minimum (défaut: 4.0)
  cvss_network_min: 7.0   # Score min pour CVE réseau AV:N (défaut: 7.0)
```

### Filtre temporel

```yaml
  date_min: "2015-01-01"  # Date minimale des CVE
```

### Cache

```yaml
  vendor_cve_limit: 2000   # Limite CVE par vendor (0 = illimité)
```

### Mapping OS → Vendor NVD

```yaml
  os_vendor_map:
    windows: microsoft
    dsm: synology
    fortios: fortinet
    linux: linux
    ubuntu: canonical
    debian: debian
    centos: centos
    redhat: redhat
    ios: cisco
    esxi: vmware
    proxmox: proxmox
    android: google
    macos: apple
    freebsd: freebsd
```

Utilisé quand `os_version_id` est NULL. Recherche insensible à la casse.

### Matching de versions

```yaml
  version_match_required: true    # Mode strict (rejet si pas de match)
  version_match_min_chars: 4     # Caractères communs minimum pour match version
  product_match_bonus: true      # Bonus si produit CVE match asset
  product_match_min_chars: 6    # Caractères communs minimum pour bonus produit
```

### Mode

```yaml
  dry_run: false          # Mode test (pas d'insertion en base)
  verbose: true           # Logs détaillés
```

---

## 🤖 **Section `mistral`**

```yaml
mistral:
  model: "mistral-large-latest"  # Modèle à utiliser
  delay_seconds: 15.0            # Délai entre appels API (secondes)
  max_retries: 3                 # Tentatives en cas d'erreur
  batch_max: 0                   # 0 = illimité
  max_tokens: 512               # Tokens max par réponse
  force: false                  # Réanalyser les corrélations existantes
```

---

## 📄 **Section `rapport`**

```yaml
rapport:
  output_dir: "documents"       # Répertoire de sortie des PDF
  score_min: 0.0                # Score minimum pour apparaître dans le rapport
  statuts_inclus:               # Statuts inclus dans les rapports
    - "confirme"
    - "informatif"
    - "mitige"
```
