---
title: Ajouter un fabricant
parent: Guides d'utilisation
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

### Via le site NVD

1. Aller sur [nvd.nist.gov/vuln/search](https://nvd.nist.gov/vuln/search)
2. Chercher une CVE connue du fabricant (ex: `Synology DSM vulnerability`)
3. Ouvrir une CVE et scroller jusqu'à **CPE Configuration**
4. Lire l'entrée CPE : `cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*`
5. **Résultat** : `synology`
6. Ajoute le fabricant depuis le référentiel des fabricants : 
```html
http://URL/ui/vendors
```

