---
title: Ajouter un client, site et asset
parent: Guides opérationnels
nav_order: 1
---

# 🎯 Ajouter un client, site et asset

**Workflow complet de premier inventaire**

---

## 1️⃣ **Créer le client**

1. Aller sur `/ui/clients`
2. Cliquer sur **➕ Nouveau client**
3. Renseigner :
   - **Nom** (obligatoire)
   - Contact (nom, email, téléphone)
   - Adresse (optionnel)
4. Sauvegarder

---

## 2️⃣ **Créer le site**

1. Aller sur `/ui/sites`
2. Cliquer sur **➕ Nouveau site**
3. Renseigner :
   - **Client** : sélectionner le client créé
   - **Nom** (obligatoire)
   - Ville, Code postal, Pays
   - Contact local (optionnel)
4. Sauvegarder

---

## 3️⃣ **Vérifier les référentiels**

Avant de créer les assets, vérifier que les données existent :

| Référentiel | Où vérifier | Si absent |
|-------------|-------------|-----------|
| **Fabricant** | `/ui/vendors` | [Ajouter un fabricant]({{ site.baseurl }}/guides/nouveau-fabricant) |
| **OS & Versions** | `/ui/os-versions` | Créer l'entrée ou utiliser version libre |
| **Type d'équipement** | `/ui/equipment-types` | [Configurer un type]({{ site.baseurl }}/guides/equipment-type) |

---

## 4️⃣ **Créer les assets**

Pour chaque équipement :

1. Aller sur `/ui/assets`
2. Cliquer sur **➕ Nouvel asset**
3. Renseigner :

### Localisation
- **Client** → sélection via typeahead
- **Site** → se débloque après sélection du client

### Identification
- **Nom interne** (obligatoire)
- **Type d'équipement**
- **Fabricant**
- **Modèle**

### Système
- **Système d'exploitation**
- **Version OS**
- **Version firmware** (optionnel)
- **Version BIOS** (optionnel)

### Réseau
- **Adresse IP**
- **Adresse MAC**
- **Hostname**

### Métadonnées
- **Numéro de série**
- **Date installation**
- **Date fin garantie**
- **Niveau criticité** : faible/moyen/élevé/critique
- **Statut opérationnel** : actif/inactif/maintenance/hors_service
- **Notes**

4. Sauvegarder

---

## 5️⃣ **Importer depuis Excel** (optionnel)

Pour un inventaire massif :

1. Télécharger le template : `/api/import/template`
2. Remplir le fichier Excel
3. Importer via `/ui/import`

Voir [Import d'assets]({{ site.baseurl }}/guides/import-assets)

---

## ✅ **Vérification**

- Vérifier que l'asset apparaît dans `/ui/assets`
- Vérifier que le client/site apparaît dans les listes déroulantes
- Lancer une corrélation test pour valider les données
