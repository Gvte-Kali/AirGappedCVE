---
title: cve_sync.py
nav_order: 3
parent: NVD Sync
---

## __nvd_sync.py__ - Synchronisation des CVE NVD

Script d'import des **CVE** depuis les fichiers JSON du NVD, avec **filtrage automatique** basé sur les vendors/products présents dans le référentiel (`product_vendors` et `product_models`).

### Chronologie

1. **Initialisation** : Vérification du répertoire NVD et chargement des filtres depuis la base de données (`product_vendors` et `product_models`).

2. **Traitement des fichiers** :
   - Parcours des fichiers JSON NVD.
   - Pour chaque CVE, vérification des correspondances avec les filtres (vendors/products).
   - Extraction des informations (ID, description, scores CVSS, CWE, versions affectées, etc.).

3. **Insertion/Update** :
   - Insertion ou mise à jour des CVE dans la table `cve` (avec `ON DUPLICATE KEY UPDATE`).
   - Liaison des CWE associés dans `cve_cwe`.

4. **Finalisation** : Affichage des statistiques (CVE parcourues, importées, ignorées).

---