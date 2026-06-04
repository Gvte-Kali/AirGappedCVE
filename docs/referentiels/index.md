---
title: Référentiels métier
nav_order: 4
has_children: true
---

# 🗃️ Référentiels métier

**Données de base du système** - À renseigner avant d'utiliser le moteur de corrélation.

---

## 📋 **Ordre de saisie recommandé**

Suivre les dépendances entre tables :

```
1. Fabricants (product_vendors)
   │
   ▼
2. Modèles (product_models)
   │
   ▼
3. OS & Versions (os_versions)
   │
   ▼
4. Types d'équipements (equipment_types)
   │
   ▼
5. Clients
   │
   ▼
6. Sites
   │
   ▼
7. Assets
```

---

## 📖 **Pages disponibles**

| Page | Description |
|------|-------------|
| [🏢 Clients & Sites]({{ site.baseurl }}/referentiels/clients-sites) | Hiérarchie, contacts, cascade |
| [💻 Assets]({{ site.baseurl }}/referentiels/assets) | Champs, versions OS, criticité |
| [🏭 Fabricants]({{ site.baseurl }}/referentiels/fabricants) | Nomenclature NVD, identifier le bon vendor |
| [🏷️ Modèles]({{ site.baseurl }}/referentiels/modeles) | nvd_product, cpe_part, types produit |
| [📊 OS & Versions]({{ site.baseurl }}/referentiels/os-versions) | Référentiel normalisé, formats |
| [⚙️ Types d'équipements]({{ site.baseurl }}/referentiels/equipment-types) | Configuration du moteur de corrélation |
