---
title: download_nvd.py
nav_order: 1
parent: NVD Sync
---
## **download_nvd.py** - Téléchargement NVD/CWE

Script de téléchargement des données **CVE (NVD)** et **CWE (MITRE)**.
Stocke les fichiers bruts (JSON/XML) dans `/data/nvd/{raw,cwe}` **sans modifier la base de données**.

### Chronologie
1. **Initialisation** : Vérification et création des répertoires `data/nvd/raw` et `data/nvd/cwe`.
2. **Téléchargement CVE** :
   - Détection des fichiers existants pour reprise.
   - Requête initiale à l'API NVD pour obtenir le nombre total de CVE.
   - Téléchargement séquentiel par pages de 2000 entrées.
   - Sauvegarde dans `cve_full_page_XXXX.json`.
3. **Téléchargement CWE** :
   - Téléchargement du ZIP depuis MITRE.
   - Extraction et sauvegarde du XML dans `cwe/cwec_latest.xml`.
4. **Finalisation** : Vérification de la date de la dernière CVE et résumé.