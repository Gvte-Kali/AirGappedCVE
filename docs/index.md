---
title: Accueil
layout: home
nav_order: 1
---

# Asset & Vulnerability Manager
{: .fs-9 }

Système de gestion d'assets informatiques et de vulnérabilités CVE,
conçu pour les prestataires informatiques gérant des équipements en environnement **air-gappé**.
{: .fs-6 .fw-300 }

---

## Présentation

L'**Asset & Vulnerability Manager** est une application web permettant à un prestataire informatique de :

- **Inventorier** les équipements de ses clients (serveurs, NAS, PC, caméras, lecteurs biométriques…)
- **Corréler automatiquement** les CVE du NVD avec les assets présents en base
- **Analyser** les vulnérabilités détectées grâce à Mistral AI, en tenant compte du contexte air-gap
- **Prioriser et tracer** les actions correctives par client et par site

Le système est conçu pour fonctionner **sans agent déployé chez les clients**. Toutes les données sont saisies manuellement ou importées lors des interventions sur site.

---

## Contrainte fondamentale : Air-Gap

Tous les environnements clients sont **physiquement isolés d'Internet**.
Cette contrainte influence toute la logique d'analyse de risque :

{: .highlight }
Une CVE exploitable uniquement via Internet (vecteur `AV:N`) est **systématiquement pénalisée** dans le scoring. Une CVE exploitable en réseau local (`AV:L`) ou physiquement (`AV:P`) est au contraire **bonifiée**.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Raspberry Pi 5                      │
│                  Ubuntu Server                       │
│                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────────┐  │
│  │ MariaDB  │◄───│ FastAPI  │◄───│   Frontend   │  │
│  │          │    │          │    │   (HTML/JS)  │  │
│  └──────────┘    └──────────┘    └──────────────┘  │
│       ▲               │                             │
│       │          ┌────▼─────┐    ┌──────────────┐  │
│       └──────────│ Scripts  │    │   Grafana    │  │
│                  │ Python   │    │  (à venir)   │  │
│                  │ + Mistral│    └──────────────┘  │
│                  └──────────┘                       │
└─────────────────────────────────────────────────────┘
```

| Composant | Rôle |
|-----------|------|
| **MariaDB** | Base de données centrale — assets, CVE, corrélations |
| **FastAPI** | API REST — expose toutes les opérations CRUD |
| **Scripts Python** | Moteur de corrélation CVE + analyse Mistral AI |
| **Frontend** | Interface web custom (HTML/JS/Bootstrap) |
| **Grafana** | Dashboards de visualisation *(à venir)* |
| **Cron** | Planification des scripts automatiques |

---

## Stack technique

| Technologie | Usage |
|-------------|-------|
| Python 3.12 | Scripts, API FastAPI |
| MariaDB 10.11 | Base de données |
| FastAPI | API REST |
| Mistral AI | Analyse contextuelle des vulnérabilités |
| Bootstrap 5 | Interface utilisateur |
| Grafana | Visualisation *(à venir)* |
| systemd | Gestion du service en production |
| Raspberry Pi 5 | Serveur de production |

---

## Navigation

| Section | Description |
|---------|-------------|
| [Installation]({{ site.baseurl }}/installation) | Prérequis, déploiement, configuration |
| [Base de données]({{ site.baseurl }}/database) | Schéma, tables, vues |
| [Référentiels métier]({{ site.baseurl }}/referentiels) | Clients, assets, fabricants, OS |
| [Moteur de corrélation]({{ site.baseurl }}/correlation) | Les 3 phases, scoring, Mistral |
| [API FastAPI]({{ site.baseurl }}/api) | Endpoints, paramètres, pagination |
| [Interface utilisateur]({{ site.baseurl }}/ui) | Pages, filtres, actions |
| [Guides opérationnels]({{ site.baseurl }}/guides) | Workflows, bonnes pratiques |
| [Référence technique]({{ site.baseurl }}/reference) | Config, variables, glossaire |
| [Grafana]({{ site.baseurl }}/grafana) | Dashboards *(à venir)* |
