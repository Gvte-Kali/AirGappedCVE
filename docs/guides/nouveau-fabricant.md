---
title: Ajouter un fabricant
parent: Guides opérationnels
nav_order: 2
---

# 🏭 Ajouter un fabricant

**Ajouter un fabricant et ses données NVD pour la corrélation CVE**

---

## ⚠️ **Pourquoi c'est critique**

Le `nvd_vendor` est la **clé primaire** de la corrélation CVE.

- ❌ Identifiant incorrect ou absent = **aucune CVE trouvée**
- ✅ Identifiant exact = corrélation fonctionnelle

---

## 1️⃣ **Trouver le `nvd_vendor` exact**

### Méthode recommandée — Via NVD

1. Aller sur [nvd.nist.gov/vuln/search](https://nvd.nist.gov/vuln/search)
2. Chercher une CVE connue du fabricant (ex: `Synology DSM vulnerability`)
3. Ouvrir une CVE et scroller jusqu'à **CPE Configuration**
4. Lire l'entrée CPE : `cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*`
   ```
                          ↑
                      nvd_vendor
   ```
5. **Résultat** : `synology`

### Méthode alternative — Via la base locale

```sql
SELECT DISTINCT fabricant
FROM cve
WHERE fabricant LIKE '%synology%';
```

### Règles de format

- ✅ Tout en **minuscules**
- ✅ Pas d'espaces (remplacés par tirets ou underscores)
- Exemples : `microsoft`, `synology`, `fortinet`, `zkteco`, `axis`

---

## 2️⃣ **Créer le fabricant**

1. Aller sur `/ui/vendors`
2. Cliquer sur **➕ Nouveau fabricant**
3. Renseigner :
   - **Nom** : nom affiché (ex: `Synology`)
   - **nvd_vendor** : identifiant NVD exact (ex: `synology`)
   - **Description** (optionnel)
4. Sauvegarder

---

## 3️⃣ **Vérifier les CVE disponibles**

```sql
SELECT COUNT(*) as nb_cve, fabricant
FROM cve
WHERE fabricant = 'synology'
GROUP BY fabricant;
```

Si `nb_cve = 0` :
- Vérifier l'orthographe du `nvd_vendor`
- Synchroniser le référentiel NVD : [Sync NVD]({{ site.baseurl }}/guides/sync-nvd)

---

## 4️⃣ **Ajouter les modèles (optionnel)**

Pour chaque modèle du fabricant :

1. Aller sur `/ui/models`
2. Cliquer sur **➕ Nouveau modèle**
3. Renseigner :
   - **Fabricant** : sélectionner le fabricant créé
   - **Nom** : nom affiché (ex: `DS220+`)
   - **nvd_product** : produit NVD (ex: `diskstation_manager`)
   - **cpe_part** : partie CPE (ex: `o` pour OS, `a` pour application)
   - **Type de produit** (optionnel)
   - **CPE base** (optionnel)

---

## 5️⃣ **Ajouter les versions OS (optionnel)**

Pour chaque version :

1. Aller sur `/ui/os-versions`
2. Cliquer sur **➕ Nouvelle version**
3. Renseigner :
   - **Fabricant** : sélectionner le fabricant
   - **Nom** : nom affiché (ex: `DSM 7.2.2`)
   - **nvd_vendor** : vendor NVD (ex: `synology`)
   - **nvd_product** : produit NVD (ex: `diskstation_manager`)
   - **Version** : version exacte (ex: `7.2.2-72806`)
   - **Type OS** : os/firmware/bios

---

## ✅ **Test final**

Créer un asset avec ce fabricant/modèle/version et lancer une corrélation test.
