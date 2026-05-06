---
title: Console Scripts
parent: Interface utilisateur
nav_order: 5
---

# Console Scripts
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Accès

`/scripts/console` — lien **Console** dans la navbar.

---

## Rôle

La console permet de lancer et surveiller les scripts Python du pipeline depuis l'interface web, sans accès SSH au serveur.

---

## Scripts disponibles

| Script | Description |
|--------|-------------|
| **Corrélation** | Lance `correlate_and_analyze.py correlate` — Phase 1+2 uniquement |
| **Analyse Mistral** | Lance `correlate_and_analyze.py analyze` — Phase 3 uniquement |
| **Pipeline complet** | Lance `correlate_and_analyze.py run-all` — Phases 1+2+3 |

Les mêmes scripts sont aussi accessibles directement depuis la page Vulnérabilités via les boutons en haut à droite.

---

## Suivi de l'exécution

### Barre de progression

Une barre de progression animée s'affiche pendant l'exécution. La progression est **simulée** (incréments de 5% toutes les 2 secondes) car le script Python ne remonte pas de pourcentage exact — seul le statut terminé/en cours est connu.

### Logs en temps réel

Les logs du script sont affichés en temps réel dans une zone de texte monospace (scroll automatique). Le polling est effectué toutes les **2 secondes** sur l'endpoint `GET /api/correlations/run-status`.

### États de fin

| Résultat | Couleur barre | Déclencheur |
|----------|--------------|-------------|
| Succès | Verte | Message contient "succès" |
| Erreur | Rouge | Tout autre message de fin |

---

## Gestion des exécutions concurrentes

Si un script est déjà en cours d'exécution, tout nouveau lancement retourne un **HTTP 409** et un message d'avertissement. Un seul pipeline peut tourner à la fois.

---

## Logs persistants

Les logs sont aussi écrits dans `logs/FastAPI.log` côté serveur. Pour une analyse approfondie :

```bash
tail -f logs/FastAPI.log
```

ou via journalctl en production :

```bash
sudo journalctl -u asset-manager -f
```
