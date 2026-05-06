---
title: Ajouter un client, site et asset
parent: Guides opérationnels
nav_order: 1
---

# Ajouter un client, site et asset
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

Ce guide couvre le workflow complet de premier inventaire pour un nouveau client.

---

## Étape 1 — Créer le client

1. Aller sur `/ui/clients`
2. Cliquer sur **＋ Nouveau client**
3. Renseigner au minimum :
   - **Nom** (obligatoire) : nom de l'organisation
   - **Contact nom** + **email** + **téléphone** : contact principal
4. Sauvegarder

---

## Étape 2 — Créer le site

1. Aller sur `/ui/sites`
2. Cliquer sur **＋ Nouveau site**
3. Renseigner :
   - **Client** : sélectionner le client créé à l'étape 1
   - **Nom** (obligatoire) : nom du site (ex: `Siège Paris`, `MA-Metz`)
   - **Ville**, **Code postal**, **Pays**
   - **Contact local** : personne à joindre lors des interventions sur site
4. Sauvegarder

---

## Étape 3 — Préparer les référentiels (si nécessaire)

Avant de créer les assets, vérifier que les données de référence existent :

### Fabricant
Le fabricant du matériel doit être dans `/ui/vendors`. Vérifier via la recherche.

Si absent → [Ajouter un fabricant]({{ site.baseurl }}/guides/nouveau-fabricant).

### OS & Versions
L'OS de l'équipement doit être dans `/ui/os-versions`.

Si absent → Créer l'entrée ou utiliser la saisie en version libre dans l'asset.

### Type d'équipement
Le type doit exister dans `/ui/equipment-types`.

Si absent → Le créer avec la configuration appropriée (voir [Configurer un type d'équipement]({{ site.baseurl }}/guides/equipment-type)).

---

## Étape 4 — Créer les assets

Pour chaque équipement inventorié :

1. Aller sur `/ui/assets`
2. Cliquer sur **➕ Nouvel asset**
3. Renseigner dans l'ordre :

### Localisation
- **Client** → sélectionner via typeahead
- **Site** → se débloque après sélection du client

### Identification
- **Nom interne** (obligatoire) : convention recommandée `TYPE-SITE-NUMERO` (ex: `SRV-METZ-01`, `NAS-PARIS-01`)
- **Type d'équipement** : sélectionner depuis le référentiel

### Fabricant & Modèle
- **Fabricant** : sélectionner via typeahead (obligatoire pour la corrélation CVE)
- **Modèle** : optionnel mais recommandé pour affiner la corrélation

### Réseau
- **IP**, **MAC**, **Hostname** : renseigner si disponible

### OS & Versions
- **Système d'exploitation** : typeahead niveau 1 (ex: `Windows Server`)
- **Version OS** :
  - Si disponible dans le référentiel → typeahead niveau 2 (ex: `2022 (windows_server_2022)`) ← **recommandé**
  - Sinon → saisir la version exacte dans le champ libre (ex: `7.2.2-72806 Update 3`)
  - Le lien ❓ affiche les formats attendus par fabricant

### Criticité & Statut
- **Criticité** : évaluer selon l'importance de l'équipement dans l'infrastructure
  - `critique` : Active Directory, contrôleur de domaine, firewall périmétrique
  - `eleve` : serveurs applicatifs, NAS primaires
  - `moyen` : postes de travail, équipements secondaires
  - `faible` : équipements de bureau, imprimantes
- **Statut** : `actif` par défaut

4. Sauvegarder

---

## Étape 5 — Lancer la corrélation

Une fois tous les assets créés :

1. Aller sur `/ui/vulns`
2. Cliquer sur **⚡ Tout exécuter**
3. Confirmer le lancement
4. Attendre la fin du pipeline (corrélation + analyse Mistral)
5. Les vulnérabilités détectées apparaissent dans le tableau

---

## Récapitulatif des données minimales pour la corrélation

| Champ | Obligatoire pour la corrélation | Impact |
|-------|--------------------------------|--------|
| Fabricant (`vendor_id`) | ✅ | Sans fabricant = aucune corrélation |
| OS normalisé (`os_version_id`) | Recommandé | Corrélation `affirme` si renseigné |
| Version libre (`version_os`) | Fallback | Corrélation `informatif` si pas de FK |
| Type d'équipement | ✅ | Détermine la stratégie de corrélation |
| Criticité | Recommandé | Influence le score de pré-triage |
