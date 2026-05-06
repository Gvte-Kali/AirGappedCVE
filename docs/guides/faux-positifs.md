---
title: Gérer les faux positifs
parent: Guides opérationnels
nav_order: 5
---

# Gérer les faux positifs
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Qu'est-ce qu'un faux positif ?

Un faux positif est une corrélation CVE détectée par le moteur qui **ne s'applique pas réellement** à l'asset concerné. Les causes les plus fréquentes :

| Cause | Exemple |
|-------|---------|
| Mauvais produit NVD | CVE `windows_server_2016` corrélée sur un serveur Windows Server 2022 |
| Version patchée | CVE `before 6.2.4` corrélée sur un DSM en `7.2.2` (supérieur à 6.2.4) |
| Composant non présent | CVE sur un plugin non installé |
| Vendor trop large | CVE Synology sur un composant non utilisé |

---

## Comment les identifier

### Via la colonne "Confirmé IA"

- **✓ Oui** (`affirme`) + Mistral dit `faux_positif` → Faux positif probable, Mistral a détecté l'incohérence
- **— Non** (`informatif`) → Corrélation incertaine, à vérifier manuellement

### Via l'analyse Mistral

Ouvrir le détail (bouton 🔍) et lire la justification :
```
[Verdict Mistral: faux_positif] [Ajustement: -2.0]
La CVE cible Windows Server 2016, or l'asset utilise Windows Server 2022,
non concerné par cette vulnérabilité.
```

### Via le diagnostic en base

```sql
-- Voir les CVE rejetées pour un asset (debug)
SELECT cve_id, raison, details, asset_version, cve_versions
FROM correlation_rejects
WHERE asset_id = X
ORDER BY date_rejet DESC;
```

---

## Qualifier un faux positif

### Méthode rapide — Bouton ✖

Sur le tableau des vulnérabilités, le bouton ✖ de chaque ligne passe directement le statut en `faux_positif` sans ouvrir le détail.

### Méthode complète — Via le modal

1. Ouvrir le détail (bouton 🔍)
2. Changer le **Statut** → `faux_positif`
3. Optionnel : renseigner les **Notes** pour expliquer la raison
4. Sauvegarder

---

## Override opérateur

Si une corrélation a été confirmée par Mistral (`statut = confirme`) mais que vous estimez que c'est un faux positif, utiliser l'**Override utilisateur** :

1. Ouvrir le détail
2. Dans **Override utilisateur** → sélectionner `faux_positif`
3. Sauvegarder

L'override prime sur le statut automatique dans la vue `v_vulnerabilites_tableau` (`COALESCE(override_utilisateur, statut)`).

{: .note }
Le statut en base reste `confirme` — l'override est une couche supplémentaire qui n'efface pas l'analyse Mistral. Cela permet de tracer les désaccords opérateur/IA.

---

## Faux positifs systématiques — Corriger la source

Si des faux positifs se répètent pour le même type d'équipement, c'est souvent un problème de configuration du moteur. Actions correctives :

### Problème : CVE d'un mauvais produit Windows

**Symptôme :** CVE `windows_server_2016` sur un serveur `windows_server_2022`.

**Cause :** Le filtre produit fonctionne via `os_nvd_product` — si les deux versions ont le même `nvd_product` dans `os_versions`, elles se confondent.

**Solution :** Vérifier que chaque version Windows a son propre `nvd_product` dans `os_versions` (`windows_server_2016` vs `windows_server_2022`).

### Problème : Version patché toujours détectée

**Symptôme :** CVE `before 6.2.4` détectée sur DSM `7.2.2`.

**Cause :** `use_version_os = 0` sur le type NAS → pas de comparaison de version → CVE retenue par prudence.

**Solution :** Activer `use_version_os = 1` sur le type NAS ET s'assurer que `version_os` est renseigné sur l'asset.

### Problème : Vendor trop large

**Symptôme :** CVE d'un produit Synology non pertinent (ex: `surveillance_station`) corrélée sur un NAS.

**Cause :** Le filtre produit ne trouve pas de match exact → fallback fuzzy trop permissif.

**Solution :** Renseigner `os_version_id` sur l'asset → le filtre produit FK devient exact et ne retient que `diskstation_manager`.

---

## Faux positifs en masse — Nettoyage

Si un run de corrélation a généré beaucoup de faux positifs suite à un mauvais paramétrage :

```sql
-- Supprimer toutes les corrélations d'un asset pour relancer proprement
DELETE FROM correlations WHERE asset_id = X;
DELETE FROM correlation_rejects WHERE asset_id = X;
```

Corriger le paramétrage, puis relancer la corrélation.

{: .warning }
Ne pas supprimer des corrélations validées manuellement par un opérateur sans confirmation.
