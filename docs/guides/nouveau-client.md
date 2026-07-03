---
title: Ajouter un client, site et asset
parent: Guides opérationnels
nav_order: 1
---

# 🎯 Ajouter un client, site et asset

**Workflow complet**

---
## 1️⃣ **Créer le client**

## 2️⃣ **Créer le site**

Tous les sites du clients devront être renseignés avant de renseigner les assets

---

## 3️⃣ **Vérifier les référentiels**

Avant de créer les assets, vérifier que les données existent.
Si le fabricant et le modèle n'existent pas, allez les créer avant de créer l'asset.

| Référentiel | Où vérifier | Si absent |
|-------------|-------------|-----------|
| **Fabricant** | `/ui/vendors` | [Ajouter un fabricant]({{ site.baseurl }}/guides/nouveau-fabricant) |
| **OS & Versions** | `/ui/os-versions` | Créer l'entrée ou utiliser version libre |
| **Type d'équipement** | `/ui/equipment-types` | [Configurer un type]({{ site.baseurl }}/guides/equipment-type) |

---

## 4️⃣ **Créer les assets**


Un asset a l'obligation d'être assigné à : 
1. Un fabricant
2. Un modèle ( qui est lié au fabricant)
3. Un client
4. Un site ( qui est lié au client )

On pourra donc assigner les assets à toutes ces caractéristiques si elles existent.
