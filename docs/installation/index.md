---
title: Installation & Déploiement
nav_order: 2
has_children: true
---

# 📥 Installation & Déploiement

**Installation complète en 4 étapes sur Ubuntu Server (Raspberry Pi 5 recommandé)**

---

## 📋 **Vue d'ensemble**

```
Ubuntu Server (Raspberry Pi 5)
├── MariaDB 11.x          → Base de données
├── Python 3.12 + venv   → API + scripts
└── systemd              → Service
```

---

## 🚀 **Étapes**

1. **[Prérequis]({{ site.baseurl }}/installation/prerequis)** — Système, MariaDB
2. **[Installation]({{ site.baseurl }}/installation/installation)** — Clone, venv, dépendances
3. **[Configuration]({{ site.baseurl }}/installation/configuration)** — `.env`, base de données
4. **[Déploiement]({{ site.baseurl }}/installation/deploiement)** — Service systemd
