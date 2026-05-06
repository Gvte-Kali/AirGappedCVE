---
title: config.yml
parent: Moteur de corrélation
nav_order: 7
---

# Référence config.yml
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

Le fichier `scripts/config.yml` contrôle tous les paramètres du moteur de corrélation et de l'analyse Mistral. Il est versionné et peut être modifié sans redémarrage du service.

---

## Section `correlation`

### Filtres CVSS

```yaml
correlation:
  cvss_min: 4.0
```

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `cvss_min` | float | 4.0 | Score CVSS v3 minimum pour qu'une CVE soit chargée en cache. Les CVE sous ce seuil sont ignorées. |
| `cvss_network_min` | float | 7.0 | Score minimum pour les CVE réseau (`AV:N`). Les CVE réseau sous ce seuil sont exclues — trop peu pertinentes en air-gap. |

### Filtre temporel

```yaml
  date_min: "2015-01-01"
```

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `date_min` | string (date) | `"2015-01-01"` | Date de publication minimale des CVE. Les CVE plus anciennes sont ignorées. |

### Cache

```yaml
  vendor_cve_limit: 2000
```

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `vendor_cve_limit` | int | 2000 | Nombre maximum de CVE chargées par vendor, triées par score DESC. **0 = illimité.** Pour Microsoft (~13 000 CVE éligibles), mettre à 0 pour ne manquer aucune CVE. Attention à la performance. |

### Mapping OS textuel → vendor NVD

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

Utilisé quand `os_version_id` est NULL pour détecter le vendor NVD depuis `systeme_exploitation` ou `version_os`. La recherche est insensible à la casse.

Pour ajouter un nouveau système : ajouter une entrée `keyword: nvd_vendor` où `keyword` est une sous-chaîne du nom OS et `nvd_vendor` est l'identifiant exact dans le NVD.

### Matching de versions

```yaml
  version_match_required: true
  version_match_min_chars: 4
  product_match_bonus: true
  product_match_min_chars: 6
```

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `version_match_required` | bool | true | Si true, une CVE sans version matchant l'asset est rejetée (mode strict). Si false, toutes les CVE du vendor/produit sont retenues. |
| `version_match_min_chars` | int | 4 | Nombre minimum de caractères alphanumériques communs entre un token de version CVE et un token de version asset pour considérer un match. |
| `product_match_bonus` | bool | true | Active le bonus de score si le produit CVE partage des caractères avec l'asset. |
| `product_match_min_chars` | int | 6 | Nombre minimum de caractères communs pour le bonus produit. |

### Mode et verbosité

```yaml
  dry_run: false
  verbose: true
```

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `dry_run` | bool | false | Si true, affiche les corrélations sans les insérer en base. Utile pour tester la configuration. |
| `verbose` | bool | false | Si true, affiche les détails de chaque passe de corrélation par asset (nombre de CVE retenues, rejetées…). |

---

## Section `mistral`

```yaml
mistral:
  model: "mistral-large-latest"
  delay_seconds: 15.0
  max_retries: 3
  batch_max: 0
  max_tokens: 512
  force: false
```

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `model` | string | `"mistral-large-latest"` | Modèle Mistral à utiliser. Peut être surchargé par `MISTRAL_MODEL` dans `.env`. |
| `delay_seconds` | float | 15.0 | Délai en secondes entre chaque appel API. Adapter selon votre quota (clé gratuite ≈ 6 req/min → 10s minimum). Peut être surchargé par `MISTRAL_DELAY`. |
| `max_retries` | int | 3 | Nombre maximum de tentatives en cas de rate limit (HTTP 429). Backoff progressif : 20s, 40s, 60s. |
| `batch_max` | int | 0 | Nombre maximum de corrélations à analyser par run. **0 = illimité.** Utile pour contrôler la consommation API. Peut être surchargé par `MISTRAL_BATCH_MAX`. |
| `max_tokens` | int | 512 | Nombre maximum de tokens en sortie par appel Mistral. 512 est suffisant pour le format JSON attendu. |
| `force` | bool | false | Si true, réanalyse les corrélations déjà analysées (statut != nouveau). Utile pour forcer une ré-analyse avec un nouveau prompt. |

---

## Section `rapport`

```yaml
rapport:
  output_dir: "documents"
  statuts_inclus:
    - "confirme"
    - "informatif"
    - "mitige"
  score_min: 0.0
```

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `output_dir` | string | `"documents"` | Répertoire de sortie des PDF générés, relatif à la racine du projet. |
| `statuts_inclus` | list | voir ci-dessus | Statuts de corrélations inclus dans les rapports PDF. |
| `score_min` | float | 0.0 | Score contextuel minimum pour apparaître dans un rapport PDF. |

---

## Priorité des paramètres

```
Variable d'environnement (.env)  >  config.yml  >  valeur par défaut du code
```

Les variables d'environnement `MISTRAL_MODEL`, `MISTRAL_DELAY` et `MISTRAL_BATCH_MAX` surchargent les valeurs de `config.yml`.
