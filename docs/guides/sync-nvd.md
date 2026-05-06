---
title: Synchronisation NVD
parent: Guides opérationnels
nav_order: 7
---

# Synchronisation NVD
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Principe

Le moteur de corrélation CVE travaille sur une **copie locale** de la base NVD (National Vulnerability Database). Cette copie doit être mise à jour régulièrement pour disposer des dernières CVE publiées.

La synchronisation est réalisée par des scripts Python dédiés, distincts du pipeline de corrélation.

---

## Scripts de synchronisation

{: .note }
Les scripts de synchronisation NVD ne sont pas encore documentés dans cette version. Cette section sera complétée lors de leur implémentation formelle. Les informations ci-dessous décrivent le comportement actuel de la base.

---

## État actuel de la base CVE

```sql
-- Nombre de CVE en base
SELECT COUNT(*) as total FROM cve;
-- Résultat : ~932 000 CVE

-- CVE par vendor (top 10)
SELECT fabricant, COUNT(*) as nb
FROM cve
GROUP BY fabricant
ORDER BY nb DESC
LIMIT 10;

-- CVE récentes (30 derniers jours)
SELECT COUNT(*) as nb_recentes
FROM cve
WHERE date_publication >= DATE_SUB(NOW(), INTERVAL 30 DAY);

-- Dernière CVE importée
SELECT cve_id, date_publication, updated_at
FROM cve
ORDER BY updated_at DESC
LIMIT 1;
```

---

## Vérifier la couverture d'un vendor

Avant de lancer une corrélation sur un nouvel équipement, vérifier que des CVE existent pour son vendor :

```sql
-- CVE disponibles pour un vendor
SELECT COUNT(*) as nb_cve, fabricant
FROM cve
WHERE fabricant = 'synology'
GROUP BY fabricant;

-- CVE par produit pour un vendor
SELECT produit, COUNT(*) as nb
FROM cve
WHERE fabricant = 'synology'
GROUP BY produit
ORDER BY nb DESC;
```

Si le résultat est 0, les CVE de ce vendor ne sont pas encore importées.

---

## Table `historique_analyses`

Chaque synchronisation est enregistrée dans `historique_analyses` :

```sql
-- Dernières synchronisations
SELECT type_analyse, statut, nb_nouveaux, nb_mis_a_jour,
       duree_secondes, date_execution
FROM historique_analyses
WHERE type_analyse IN ('sync_cve', 'sync_cwe')
ORDER BY date_execution DESC
LIMIT 10;
```

---

## Paramètres de filtrage des CVE

Le moteur n'utilise pas toutes les CVE importées — il applique des filtres lors du chargement en cache :

| Filtre | Paramètre | Défaut | Effet |
|--------|-----------|--------|-------|
| Score minimum | `cvss_min` | 4.0 | Ignore les CVE de sévérité très faible |
| Score réseau min | `cvss_network_min` | 7.0 | Ignore les CVE réseau de sévérité MEDIUM (peu pertinentes en air-gap) |
| Date minimum | `date_min` | `2015-01-01` | Ignore les CVE très anciennes |
| Limite par vendor | `vendor_cve_limit` | 2000 | Limite le cache mémoire par vendor |

Ces paramètres sont configurables dans `scripts/config.yml`.

---

## À venir

La documentation complète de la synchronisation NVD sera ajoutée lors de l'implémentation des scripts dédiés. Elle couvrira :

- Synchronisation initiale complète depuis le NVD
- Synchronisation incrémentale (deltas quotidiens)
- Planification via Cron
- Gestion des erreurs et reprise
- Monitoring de la fraîcheur des données
