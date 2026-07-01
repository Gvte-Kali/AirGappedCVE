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

## 🎯 **À quoi ça sert ?**

Air-Gapped CVEs permet aux prestataires informatiques de :

- ✅ **Inventorier** les équipements clients (serveurs, NAS, PC, caméras, etc.)
- ✅ **Corréler automatiquement** les CVE NVD avec vos assets
- ✅ **Analyser** les vulnérabilités avec Mistral AI (contexte air-gap)
- ✅ **Prioriser** les actions correctives par client/site

**Particularité** : Fonctionne **sans agent** chez le client. Toutes les données sont saisies manuellement ou importées.

---

## 🔒 **Contrainte Air-Gap**

Les environnements clients sont **physiquement isolés d'Internet**. Impact sur le scoring :

- ❌ **Pénalisé** : CVE exploitable via Internet (`AV:N`)
- ✅ **Bonifié** : CVE exploitable en local (`AV:L`) ou physiquement (`AV:P`)

---

## 🏗️ **Architecture**

```
Raspberry Pi 5 / Ubuntu Server
├── MariaDB 11.x    → Base de données
├── FastAPI         → API REST
├── Scripts Python  → Corrélation + Mistral AI
└── Frontend HTML   → Interface web
```

---

## 📚 **Documentation**

| Section | Description |
|---------|-------------|
| [📥 Installation & Configuration]({{ site.baseurl }}/installation-configuration) | Déploiement et configuration |
| [🗃️ Base de données]({{ site.baseurl }}/database) | Tables principales |
| [⚡ Corrélation]({{ site.baseurl }}/correlation) | Comment ça marche |
| [🎯 Guides]({{ site.baseurl }}/guides) | Workflows pratiques |
| [🖥️ Interface]({{ site.baseurl }}/ui) | Utilisation quotidienne |
| [🔌 API]({{ site.baseurl }}/api) | Référence technique |
