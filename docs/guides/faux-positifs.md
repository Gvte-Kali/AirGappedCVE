---
title: Gérer les faux positifs
parent: Guides opérationnels
nav_order: 5
---

# ❌ Gérer les faux positifs

**Identifier et qualifier les corrélations qui ne s'appliquent pas réellement**

---

## ❓ **Qu'est-ce qu'un faux positif ?**

Corrélation CVE détectée qui **ne s'applique pas** à l'asset. Causes fréquentes :

| Cause | Exemple |
|-------|---------|
| Mauvais produit NVD | CVE `windows_server_2016` sur un serveur 2022 |
| Version patchée | CVE `< 6.2.4` sur un DSM `7.2.2` |
| Composant non présent | CVE sur un plugin non installé |
| Vendor trop large | CVE Synology sur un composant non utilisé |

---

## 🔍 **Comment les identifier**

### Via la colonne "Type"

| Type | Risque faux positif |
|------|-------------------|
| `Affirmé` + Mistral dit `faux_positif` | ✅ Faux positif probable |
| `Informatif` | ⚠️ À vérifier manuellement |

### Via l'analyse Mistral

Ouvrir le détail (bouton 🔍) et lire :
```
[Verdict Mistral: faux_positif] [Ajustement: -2.0]
La CVE cible Windows Server 2016, or l'asset utilise Windows Server 2022.
```

### Via le diagnostic en base

```sql
-- Voir les CVE rejetées pour un asset
SELECT cve_id, raison, details, asset_version, cve_versions
FROM correlation_rejects
WHERE asset_id = X
ORDER BY date_rejet DESC;
```

---

## ✅ **Qualifier un faux positif**

### Méthode rapide — Bouton ❌

Sur `/ui/vulns`, le bouton ❌ de chaque ligne passe directement le statut en `faux_positif`.

### Méthode complète — Via le modal

1. Ouvrir le détail (bouton 🔍)
2. Changer le **Statut** → `faux_positif`
3. Optionnel : renseigner les **Notes** pour expliquer
4. Sauvegarder

---

## 🎯 **Override opérateur**

Si Mistral a confirmé (`statut = confirme`) mais que vous estimez que c'est un faux positif :

1. Ouvrir le détail
2. Dans **Override utilisateur** → sélectionner `faux_positif`
3. Renseigner la **raison**
4. Sauvegarder

⚠️ **L'override prime** sur le verdict automatique.

---

## 📊 **Statistiques**

```sql
-- Taux de faux positifs par client
SELECT 
    c.nom AS client,
    COUNT(*) AS total_correlations,
    SUM(CASE WHEN co.statut = 'faux_positif' THEN 1 ELSE 0 END) AS faux_positifs,
    ROUND(SUM(CASE WHEN co.statut = 'faux_positif' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1) AS taux_fp
FROM correlations co
JOIN assets a ON a.id = co.asset_id
JOIN sites s ON s.id = a.site_id
JOIN clients c ON c.id = s.client_id
GROUP BY c.nom
ORDER BY taux_fp DESC;
```

---

## 💡 **Bonnes pratiques**

- ✅ **Vérifier systématiquement** les corrélations `informatif`
- ✅ **Lire la justification Mistral** avant de valider
- ✅ **Documenter la raison** dans les notes
- ❌ **Ne pas marquer comme faux positif** sans vérification
- ❌ **Ne pas supprimer** les corrélations (conserver l'historique)
