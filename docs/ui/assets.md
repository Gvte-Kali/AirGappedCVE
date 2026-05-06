---
title: Page Assets
parent: Interface utilisateur
nav_order: 2
---

# Page Assets
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Accès

`/ui/assets` — menu **Référentiels → 💻 Assets**.

---

## Filtres

Trois filtres sont disponibles en haut de la liste :

| Filtre | Type | Description |
|--------|------|-------------|
| Client | Typeahead | Filtre par client. Active le filtre Site. |
| Site | Typeahead | Filtre par site (dépend du client sélectionné) |
| Type | Select | Filtre par type d'équipement |

Un bouton 🔍 applique les filtres, un bouton ✖ réinitialise.

---

## Tableau des assets

Colonnes affichées : Nom, Client, Site, Type, Fabricant, Modèle, IP, OS, Criticité, Statut, Actions.

La colonne OS affiche :
- Si `os_version_id` renseigné : `os_version_nom + os_version_ver` (depuis la FK)
- Sinon : `systeme_exploitation + version_os` (texte libre)

Trois boutons d'action par ligne : 👁️ Voir (ouvre l'édition), ✏️ Modifier (ouvre l'édition), 🗑️ Supprimer.

---

## Modal de création / édition

### Structure du formulaire

Le modal est organisé en sections :

**Localisation**
- Client (typeahead) → débloquer Site
- Site (typeahead, dépend du client)

**Identification**
- Nom interne (obligatoire)
- Type d'équipement (select dynamique depuis `/api/equipment-types`)

**Fabricant & Modèle**
- Fabricant (typeahead) → débloquer Modèle
- Modèle (typeahead, dépend du fabricant — création inline possible)

**Réseau**
- Numéro de série, IP, MAC, Hostname

**OS & Versions**
- Système d'exploitation (typeahead niveau 1 — noms OS distincts depuis `os_versions`)
- Version OS (typeahead niveau 2 — versions filtrées par nom OS)
- Version exacte (champ libre — apparaît si aucune version normalisée sélectionnée)
- Firmware (typeahead — type_produit = firmware)
- BIOS/UEFI (typeahead — type_produit = bios)

**Dates**
- Date d'installation, Date de fin de garantie

**Statut**
- Criticité (faible / moyen / eleve / critique)
- Statut opérationnel (actif / inactif / maintenance / hors_service)

**Notes**
- Zone de texte libre

---

## Typeaheads OS — Fonctionnement détaillé

### Niveau 1 — Système d'exploitation

Le typeahead charge les noms OS distincts depuis `GET /api/os-versions`. En tapant "Windows" par exemple, il affiche tous les noms OS contenant ce terme.

Une fois un OS sélectionné, le champ Version OS est débloqué.

### Niveau 2 — Version OS

Filtrée par le nom OS sélectionné au niveau 1. Affiche les versions disponibles dans le référentiel avec le format `version (nvd_product)`.

Exemple : `2022 (windows_server_2022)`

Quand une version est sélectionnée, `os_version_id` est renseigné → corrélation en mode **affirme**.

### Champ version libre

Si le champ Version OS est laissé vide (pas de FK sélectionnée) et qu'un OS a été choisi au niveau 1, un champ texte libre apparaît avec un avertissement :

```
⚠️ Version non normalisée — corrélation en mode informatif
```

La valeur est concaténée avec le nom OS lors de la sauvegarde :
`"DSM (DiskStation Manager) 7.2.2-72806 Update 3"`

Le lien ❓ "Format attendu" pointe vers la page OS & Versions qui documente les formats attendus par fabricant.

---

## Sauvegarde

Le bouton 💾 Sauvegarder envoie :
- `POST /api/assets/` pour une création
- `PUT /api/assets/{id}` pour une modification

### Règles de priorité pour `version_os`

| Situation | Valeur envoyée |
|-----------|---------------|
| `os_version_id` renseigné | `version_os = null` (la FK suffit) |
| Champ libre renseigné, OS nom sélectionné | `version_os = "{nom OS} {version libre}"` |
| Champ libre renseigné, déjà préfixé du nom OS | `version_os = "{version libre}"` (anti-doublon) |
| Rien | `version_os = null` (valeur existante conservée) |

---

## Suppression

Une confirmation est demandée avant suppression. La suppression est en cascade — toutes les corrélations CVE de l'asset sont supprimées.

---

## Pagination

Le tableau est paginé à 20 assets par page. La pagination est gérée côté serveur via les paramètres `limit` et `skip`. Le header `X-Total-Count` retourné par l'API permet d'afficher le nombre total d'assets.
