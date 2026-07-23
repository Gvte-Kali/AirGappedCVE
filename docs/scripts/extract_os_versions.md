---
title: extract_os_versions.py
nav_order: 4
parent: NVD Sync
---

## __extract_os_versions.py__ - Extraction des versions OS

Script de peuplement de la table **`os_versions`** depuis les couples `(fabricant, produit)` des CVE.
Applique des **règles de normalisation** pour générer des noms et versions lisibles.

### Chronologie

1. **Initialisation** : Vérification/création de la table `os_versions` et chargement des couples distincts `(fabricant, produit)` depuis la table `cve`.

2. **Normalisation** :
   - Application des règles de normalisation sur chaque couple pour générer `os_nom`, `version`, et `type_produit`.

3. **Insertion** :
   - Insertion des entrées normalisées dans `os_versions` (avec `INSERT IGNORE` pour éviter les doublons).

4. **Finalisation** : Résumé des opérations (insérés, ignorés, produits sans règle de normalisation).