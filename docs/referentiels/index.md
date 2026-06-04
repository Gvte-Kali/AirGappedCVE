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

## 📖 **Voir aussi**

Les référentiels sont gérés via l'interface utilisateur :

| Référentiel | Page UI |
|-------------|---------|
| **🏢 Clients & Sites** | [/ui/clients]({{ site.baseurl }}/ui/clients) et [/ui/sites]({{ site.baseurl }}/ui/sites) |
| **💻 Assets** | [/ui/assets]({{ site.baseurl }}/ui/assets) |
| **🏭 Fabricants** | [/ui/vendors]({{ site.baseurl }}/ui/vendors) |
| **🏷️ Modèles** | [/ui/models]({{ site.baseurl }}/ui/models) |
| **📊 OS & Versions** | [/ui/os-versions]({{ site.baseurl }}/ui/os-versions) |
| **⚙️ Types d'équipements** | [/ui/equipment-types]({{ site.baseurl }}/ui/equipment-types) |
