---
title: NVD Sync
nav_order: 1
parent: Scripts
has_children: true
---

# Logique

Les scripts concernés par cette page se situent dans : __/opt/asset-manager/scripts__.
Chaque script a un fichier de log qui correspond au nom du script, et qui se situe dans __/opt/asset-manager/logs/nom_du_script.py__.

Les scripts sont censés avoir un ordre d'exécution, voir la logique de chaque script pour comprendre pourquoi.
Cet ordre est **OBLIGATOIRE** si vous voulez que tout fonctionne correctement et dans la logique pour laquelle tout a été créé : 
1. download_nvd.py
    - Importe les CVE en JSON depuis la base NVD ( dans _/data/nvd/raw_ ).
2. import_vendors_models.py
    - Importe les fabricants et les modèles existants dans les pages JSON précédemment téléchargées.
3. cve_sync.py
    - Importation des CVE dans la base de données via un parsing.
4. extract_os_versions.py
    - Importation des OS et des versions existantes dans la base NVD.

---