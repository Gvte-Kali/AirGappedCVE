---
title: Ajouter un fabricant
parent: Guides opérationnels
nav_order: 2
---

# Ajouter un fabricant
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

Ce guide explique comment ajouter un nouveau fabricant et ses données NVD associées pour permettre la corrélation CVE.

---

## Pourquoi c'est critique

Le `nvd_vendor` est la clé primaire de la corrélation CVE. Le moteur cherche les CVE avec `WHERE fabricant = nvd_vendor`. Un identifiant incorrect ou absent = **aucune CVE trouvée**.

---

## Étape 1 — Trouver le `nvd_vendor` exact

### Méthode recommandée — Via NVD

1. Aller sur [nvd.nist.gov/vuln/search](https://nvd.nist.gov/vuln/search)
2. Chercher une CVE connue du fabricant (ex: `Synology DSM vulnerability`)
3. Ouvrir une CVE et scroller jusqu'à la section **CPE Configuration**
4. Lire l'entrée CPE : `cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*`
   ```
                          ↑
                      nvd_vendor
   ```
5. Le `nvd_vendor` est : `synology`

### Méthode alternative — Via la base locale

Si des CVE sont déjà importées :

```sql
SELECT DISTINCT fabricant
FROM cve
WHERE fabricant LIKE '%synology%';
```

### Règles de format

- Tout en **minuscules**
- Pas d'espaces (remplacés par des tirets ou underscores selon l'éditeur)
- Exemples : `microsoft`, `synology`, `fortinet`, `zkteco`, `axis`

---

## Étape 2 — Créer le fabricant

1. Aller sur `/ui/vendors`
2. Cliquer sur **＋ Nouveau fabricant**
3. Renseigner :
   - **Nom** : nom affiché (ex: `Synology`)
   - **nvd_vendor** : identifiant NVD exact (ex: `synology`)
4. Sauvegarder

---

## Étape 3 — Vérifier les CVE disponibles

Après création, vérifier que des CVE existent bien en base pour ce vendor :

```sql
SELECT COUNT(*) as nb_cve, fabricant
FROM cve
WHERE fabricant = 'synology'
GROUP BY fabricant;
```

Si le résultat est 0 ou absent, les CVE n'ont pas encore été importées depuis le NVD pour ce fabricant. Une synchronisation NVD ciblée sera nécessaire (voir [Synchronisation NVD]({{ site.baseurl }}/guides/sync-nvd)).

---

## Étape 4 — Créer le modèle (recommandé)

Le modèle précise le `nvd_product` et permet un filtre produit exact lors de la corrélation.

1. Aller sur `/ui/models`
2. Cliquer sur **＋ Nouveau modèle**
3. Renseigner :
   - **Fabricant** : sélectionner le fabricant créé
   - **Nom** : nom affiché (ex: `DiskStation Manager`)
   - **nvd_product** : identifiant NVD exact (ex: `diskstation_manager`)
   - **cpe_part** : `o` pour OS, `a` pour application, `h` pour hardware
   - **Type produit** : `os`, `firmware`, `application` ou `hardware`
4. Sauvegarder

### Trouver le `nvd_product`

Même méthode que pour le `nvd_vendor` — lire le CPE dans une CVE NVD :
```
cpe:2.3:o:synology:diskstation_manager:*
                        ↑
                   nvd_product
```

---

## Étape 5 — Créer l'entrée OS & Versions (recommandé)

Pour une corrélation en mode `affirme`, ajouter l'OS dans le référentiel :

1. Aller sur `/ui/os-versions`
2. Cliquer sur **＋ Nouveau**
3. Renseigner :
   - **Nom OS** : `DSM (DiskStation Manager)`
   - **Version** : `7.2.2` (version installée sur vos équipements)
   - **nvd_vendor** : `synology`
   - **nvd_product** : `diskstation_manager`
   - **Type produit** : `os`
4. Sauvegarder

---

## Étape 6 — Configurer le type d'équipement

Vérifier que le type d'équipement associé a la bonne configuration dans `/ui/equipment-types`.

Exemple pour un NAS Synology :
- **OS (FK)** : ✅ (utilise `os_version_id`)
- **Version OS** : ✅ (utilise `version_os` texte pour comparaison)
- **Source vendor** : `materiel` (vendor depuis le fabricant matériel)

---

## Checklist récapitulative

```
[ ] nvd_vendor trouvé et vérifié sur nvd.nist.gov
[ ] Fabricant créé dans /ui/vendors
[ ] CVE vérifiées en base pour ce vendor
[ ] Modèle créé avec nvd_product correct
[ ] Entrée OS & Versions créée
[ ] Type d'équipement configuré
[ ] Asset créé avec fabricant + OS normalisé
[ ] Corrélation lancée et vérifiée
```
