---
title: Page Vulnérabilités
parent: Interface utilisateur
nav_order: 1
---

# Page Vulnérabilités
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Accès

`/ui/vulns` — lien **Vulnérabilités** dans la navbar.

C'est la page centrale du système. Elle liste toutes les corrélations CVE détectées, avec leurs scores, statuts et analyses Mistral.

---

## Cartes de statistiques

Quatre cartes en haut de page affichent en temps réel :

| Carte | Description |
|-------|-------------|
| Total Détectées | Nombre total de corrélations en base |
| Critiques | Nombre de corrélations avec `priorite = critique` |
| Impact Haut | Nombre de corrélations avec `priorite = haute` |
| Référentiel | Toujours `CVE` — rappel du référentiel utilisé |

---

## Boutons de pipeline

Trois boutons en haut à droite permettent de lancer le pipeline de corrélation :

| Bouton | Action | Commande équivalente |
|--------|--------|---------------------|
| 🔄 Corrélation | Lance uniquement la Phase 1+2 | `correlate` |
| 🤖 Analyse Mistral | Lance uniquement la Phase 3 | `analyze` |
| ⚡ Tout exécuter | Lance le pipeline complet | `run-all` |

Une confirmation est demandée avant chaque lancement. Une barre de progression avec logs en temps réel s'affiche pendant l'exécution.

{: .note }
Si une corrélation est déjà en cours, le bouton renvoie un statut 409 et un message d'avertissement.

---

## Panneau de filtres

Le panneau de filtres est **repliable** — cliquer sur l'en-tête `🔍 CRITÈRES DE RECHERCHE` l'ouvre ou le ferme. Un résumé des filtres actifs est affiché dans l'en-tête même quand le panneau est fermé.

### Filtres disponibles

| Filtre | Type | Description |
|--------|------|-------------|
| Client | Typeahead | Filtre par client (recherche dynamique) |
| Site | Typeahead | Filtre par site (indépendant du client) |
| Type d'équipement | Typeahead | Filtre par type (NAS, serveur, PC…) |
| Fabricant | Typeahead | Filtre par fabricant NVD |
| Modèle | Typeahead | Filtre par modèle (affiné si fabricant sélectionné) |
| Système d'exploitation | Typeahead | Filtre par nom OS |
| Version OS | Typeahead + texte libre | Filtre par version |
| Firmware | Typeahead | Filtre par firmware |
| Nom d'asset | Texte libre | Filtre par nom d'inventaire |
| Identifiant CVE | Texte libre | Filtre par CVE (ex: `CVE-2024-`) |
| Statut | Multi-select | nouveau / en_analyse / confirme / mitige / faux_positif / patche |
| Priorité | Multi-select | critique / haute / moyenne / basse |

### Comportement des typeaheads

- Clic sur le champ → affiche les 20 premières propositions
- Saisie → affine la recherche en temps réel (debounce 150ms)
- Sélection → déclenche automatiquement le rechargement du tableau

### Multi-select statut et priorité

Les statuts et priorités sont des cases à cocher. Par défaut :
- Statuts cochés : `nouveau`, `en_analyse`, `confirme`
- Priorités cochées : toutes

Les liens **Tout / Aucun** permettent de sélectionner ou désélectionner rapidement tous les éléments.

---

## Tableau des vulnérabilités

### Colonnes

| Colonne | Description |
|---------|-------------|
| CVE | Identifiant CVE cliquable |
| Asset / IP | Nom interne + type d'équipement |
| Localisation | Client + Site |
| Statut | Badge coloré selon le statut |
| Priorité | Badge coloré selon la priorité |
| Score CVSS | Score + sévérité avec tooltip sur la description CVE au survol |
| Confirmé IA | ✓ Oui si `type_correlation = affirme`, — Non sinon |
| Vérifié le | Date et heure de détection |
| Actions | Boutons d'action rapide |

### Badge statuts

| Statut | Couleur |
|--------|---------|
| Nouveau | Bleu |
| En analyse | Jaune |
| Confirmé | Rouge |
| Mitigé | Orange |
| Faux positif | Gris |
| Patché | Vert |

### Tooltip Score CVSS

Au survol du score CVSS, une infobulle affiche la description complète de la CVE. Utile pour comprendre rapidement la nature de la vulnérabilité sans ouvrir le détail.

---

## Actions rapides

Chaque ligne dispose de 4 boutons d'action :

| Bouton | Action | Description |
|--------|--------|-------------|
| 🔍 | Détails | Ouvre le modal de détail complet |
| ✖ | Faux positif | Passe directement en `faux_positif` |
| ✅ | Confirmer | Passe directement en `confirme` |
| 🩹 | Patché | Passe directement en `patche` |

Les boutons ✖, ✅ et 🩹 sont des actions immédiates sans confirmation. Le tableau se recharge automatiquement après chaque action.

---

## Modal de détail

Accessible via le bouton 🔍. Affiche :

### Informations asset
- Nom, type, OS, firmware, criticité
- Client et site

### Informations CVE
- Description complète
- Score CVSS v3 + vecteur
- Fabricant et produit NVD

### Analyse Mistral
- Verdict, ajustement, justification
- Recommandation d'action

### Champs éditables
- **Statut** — select (nouveau / en_analyse / confirme / mitige / faux_positif / patche)
- **Priorité** — select (critique / haute / moyenne / basse)
- **Override utilisateur** — décision manuelle qui prime sur le statut automatique (a_patcher / informatif / faux_positif)
- **Notes** — zone de texte libre pour les notes opérateur

Le bouton 💾 Sauvegarder envoie un `PATCH /api/correlations/{id}` avec les modifications.

---

## Pagination

Le tableau est paginé à 50 éléments par page. La pagination affiche les 5 pages autour de la page courante avec des boutons précédent/suivant.

---

## Barre de progression pipeline

Lors du lancement d'un pipeline, une carte s'affiche avec :
- Un spinner + message d'état
- Une barre de progression animée (progression simulée)
- Une zone de logs en temps réel (polling toutes les 2 secondes sur `/api/correlations/run-status`)

La barre passe au vert en cas de succès, au rouge en cas d'erreur. Le bouton **Masquer** permet de fermer la carte sans interrompre le pipeline.
