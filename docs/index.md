---
title: Accueil
layout: home
nav_order: 1
---

# Air-Gapped CVEs
{: .fs-9 }

**Gestion d'assets et vulnrabilits pour environnements isols**
{: .fs-6 .fw-300 }

---

## \ud83c\udf0d **\u00c0 quoi \u00e7a sert ?**

Solution con\u00e7ue pour les prestataires IT g\u00e9rant des environnements **air-gapp\u0019s** (r\u0019seaux physiquement isol\u0019s d'Internet).

- \u2705 **Inventaire centralis\u0019** : Tous les \u0019quipements clients en une seule base
- \u2705 **Corr\u0019lation automatique** : D\u0019tection des CVE NVD applicables \u00e0 vos assets
- \u2705 **Analyse contextuelle** : \u0019valuation du risque r\u0019el avec Mistral AI (adapt\u0019 air-gap)
- \u2705 **Priorisation intelligente** : Score ajust\u0019 pour les environnements isol\u0019s

**Particularit\u0019** : Fonctionne **sans agent** chez le client. Toutes les donn\u0019es sont saisies manuellement ou import\u0019es.

---

## \ud83d\udd12 **Contrainte Air-Gap**

Impact sur le scoring des vuln\u0019rabilit\u0019s :

| Type CVE | Impact | Explication |
|----------|--------|-------------|
| `AV:N` (Network) | \u274c P\u0019nalis\u0019 | Moins critique en air-gap (pas d'acc\u0018s Internet) |
| `AV:L` (Local) | \u2705 Bonifi\u0019 | Exploitable localement |
| `AV:P` (Physical) | \u2705 Bonifi\u0019 | Exploitable physiquement |

---

## \ud83c\udfd7\ufe0f **Architecture**

```
Raspberry Pi 5 / Ubuntu Server
\u251c\u2500\u2500\u2500\u2500 MariaDB 11.x    \u2192 Base de donn\u0019es (assets, CVE, corr\u0019lations)
\u251c\u2500\u2500\u2500\u2500 FastAPI         \u2192 API REST (CRUD complet)
\u251c\u2500\u2500\u2500\u2500 Scripts Python  \u2192 Moteur de corr\u0019lation + Mistral AI
\u2514\u2500\u2500\u2500\u2500 Frontend HTML   \u2192 Interface web (Bootstrap 5)
```

---

## \ud83d\udcda **Documentation**

| Section | Description | Public |
|---------|-------------|--------|
| \ud83d\udee0\ufe0f [Installation & Configuration]({{ site.baseurl }}/installation-configuration) | D\u0019ploiement et param\u0019trage | Administrateurs |
| \u26a1 [Moteur de corr\u0019lation]({{ site.baseurl }}/correlation) | Fonctionnement du moteur | Utilisateurs avanc\u0019s |
| \ud83c\udf20 [Guides]({{ site.baseurl }}/guides) | Workflows pratiques | Tous |
| \ud83d\udd0c [API]({{ site.baseurl }}/api) | R\u0019f\u0019rence technique | D\u0019veloppeurs |

---

## \ud83d\ude80 **D\u0019marrer rapidement**

1. **Installer** : Suivre le [guide d'installation]({{ site.baseurl }}/installation-configuration)
2. **Configurer** : Renseigner les r\u0019f\u0019rentiels
3. **Inventorier** : Ajouter clients, sites et assets ([Guides]({{ site.baseurl }}/guides))
4. **Analyser** : Lancer la corr\u0019lation et l'analyse Mistral

---

## \ud83d\udce1 **Ressources**

- **Documentation compl\u0018te** : [https://gvte-kali.github.io/AirGappedCVE/](https://gvte-kali.github.io/AirGappedCVE/)
- **D\u0019p\u0014t GitHub** : [Gvte-Kali/AirGappedCVE](https://github.com/Gvte-Kali/AirGappedCVE)
- **API Swagger** : `http://<IP_SERVEUR>:8000/docs`
