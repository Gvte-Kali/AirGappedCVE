---
title: Grafana
nav_order: 10
has_children: true
---

# 📊 Grafana

**Dashboards de visualisation** - À venir

---

## 🎯 **Prévu**

- Dashboards de suivi des vulnérabilités par client/site
- Visualisation des tendances (nouveaux CVE, résolutions)
- Tableaux de bord personnalisables
- Intégration avec les vues SQL existantes

---

## 📋 **Vues SQL disponibles**

Les vues suivantes sont disponibles pour Grafana :

- `v_vulnerabilites_tableau` - Données principales des vulnérabilités
- `v_assets` - Assets avec compteurs de vulnérabilités
- `v_clients` - Clients avec compteurs
- `v_sites` - Sites avec compteurs
- `v_fabricants` - Fabricants avec compteurs
- `v_modeles` - Modèles avec compteurs

---

## 🔗 **Configuration**

Pour connecter Grafana à MariaDB :

1. Installer Grafana
2. Ajouter une source de données MariaDB
3. Importer les dashboards

---

## 📅 **Statut**

⏳ **En développement** - Cette section sera complétée lors de l'implémentation.
