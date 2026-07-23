---
title: import_vendors_models.py
nav_order: 2
parent: NVD Sync
---

## __import_vendors_models.py__ - Import des vendors et modèles NVD

Script d'extraction des couples **(vendor, product)** depuis les fichiers JSON NVD et insertion dans **MariaDB** (`product_vendors` et `product_models`).
Utilise `INSERT IGNORE` pour gérer les doublons.

### Chronologie

1. **Initialisation** : Lecture des arguments, configuration de la connexion à MariaDB et vérification du dossier source `data/nvd/raw`.

2. **Étape 1 : Extraction CPE** :
   - Parcours des fichiers JSON NVD.
   - Extraction des couples *(vendor, product)* uniques depuis les strings CPE.
   - Affichage du nombre total de couples et de vendors distincts.

3. **Étape 2 : Insertion des vendors** :
   - Insertion par batches dans `product_vendors` (nom affiché et `nvd_vendor`).
   - Affichage du nombre de vendors insérés et ignorés (déjà existants).

4. **Étape 3 : Insertion des modèles** :
   - Résolution des `vendor_id` pour chaque batch.
   - Insertion par batches dans `product_models` (liens vers `vendor_id`, nom affiché, `nvd_product`, `cpe_part`, `type_produit`, `cpe_base`).
   - Affichage du nombre de modèles insérés et ignorés.

5. **Finalisation** : Résumé des opérations et fermeture de la connexion à la base de données.

---