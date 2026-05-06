---
title: Installation & Déploiement
nav_order: 2
has_children: true
---

# Installation & Déploiement

Cette section couvre l'installation complète de l'Asset & Vulnerability Manager sur un serveur Ubuntu Server (testé sur Raspberry Pi 5).

## Vue d'ensemble

Le système s'installe sur une seule machine. Tous les composants tournent en local :

```
Ubuntu Server (Raspberry Pi 5)
├── MariaDB 11.x          → base de données
├── Python 3.12 + venv    → API FastAPI + scripts
└── systemd               → gestion du service
```

## Étapes

1. [Prérequis]({{ site.baseurl }}/installation/prerequis) — système, paquets, MariaDB
2. [Installation]({{ site.baseurl }}/installation/installation) — clone, venv, dépendances
3. [Configuration]({{ site.baseurl }}/installation/configuration) — `.env`, `config.yml`
4. [Déploiement systemd]({{ site.baseurl }}/installation/deploiement) — service, démarrage automatique
