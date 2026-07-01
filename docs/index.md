---
title: Accueil
layout: home
nav_order: 1
---

# Air-Gapped CVEs
{: .fs-9 }

**Gestion d'assets et vulnérabilités pour environnements isolés**
{: .fs-6 .fw-300 }

---

## 🌍 **À quoi ça sert ?**

Solution conçue pour les prestataires IT gérant des environnements **air-gappés** (réseaux physiquement isolés d'Internet).

- ✅ **Inventaire centralisé** : Tous les équipements clients en une seule base
- ✅ **Corrélation automatique** : Détection des CVE NVD applicables à vos assets
- ✅ **Analyse contextuelle** : Évaluation du risque réel avec Mistral AI (adapté air-gap)
- ✅ **Priorisation intelligente** : Score ajusté pour les environnements isolés

**Particularité** : Fonctionne **sans agent** chez le client. Toutes les données sont saisies manuellement ou importées.

---

## 🔒 **Contrainte Air-Gap**

Impact sur le scoring des vulnérabilités :

| Type CVE | Impact | Explication |
|----------|--------|-------------|
| `AV:N` (Network) | ❌ Pénalisé | Moins critique en air-gap (pas d'accès Internet) |
| `AV:L` (Local) | ✅ Bonifié | Exploitable localement |
| `AV:P` (Physical) | ✅ Bonifié | Exploitable physiquement |

---

## 🏗️ **Architecture**

```
Raspberry Pi 5 / Ubuntu Server
├──── MariaDB 11.x    → Base de données (assets, CVE, corrélations)
├──── FastAPI         → API REST (CRUD complet)
├──── Scripts Python  → Moteur de corrélation + Mistral AI
└──── Frontend HTML   → Interface web (Bootstrap 5)
```

---

## 📚 **Documentation**

| Section | Description | Public |
|---------|-------------|--------|
| 🛠️ [Installation & Configuration]({{ site.baseurl }}/installation-configuration) | Déploiement et paramétrage | Administrateurs |
| 🗃️ [Base de données]({{ site.baseurl }}/database) | Structure et schéma | Développeurs |
| ⚡ [Moteur de corrélation]({{ site.baseurl }}/correlation) | Fonctionnement du moteur | Utilisateurs avancés |
| 🌠 [Guides]({{ site.baseurl }}/guides) | Workflows pratiques | Tous |
| 🖥️ [Interface]({{ site.baseurl }}/ui) | Utilisation quotidienne | Tous |
| 🔌 [API]({{ site.baseurl }}/api) | Référence technique | Développeurs |
| 📋 [Référentiels]({{ site.baseurl }}/referentiels) | Données de base | Utilisateurs |
| 📖 [Référence]({{ site.baseurl }}/reference) | Glossaire technique | Tous |

---

## 🚀 **Démarrer rapidement**

1. **Installer** : Suivre le [guide d'installation]({{ site.baseurl }}/installation-configuration)
2. **Configurer** : Renseigner les référentiels ([Référentiels]({{ site.baseurl }}/referentiels))
3. **Inventorier** : Ajouter clients, sites et assets ([Guides]({{ site.baseurl }}/guides))
4. **Analyser** : Lancer la corrélation et l'analyse Mistral

---

## 📡 **Ressources**

- **Documentation complète** : [https://gvte-kali.github.io/AirGappedCVE/](https://gvte-kali.github.io/AirGappedCVE/)
- **Dépôt GitHub** : [Gvte-Kali/AirGappedCVE](https://github.com/Gvte-Kali/AirGappedCVE)
- **API Swagger** : `http://<IP_SERVEUR>:8000/docs`
