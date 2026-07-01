---
title: Accueil
layout: home
nav_order: 1
---

# Air-Gapped CVEs
{: .fs-9 }

**Gestion d'assets et vuln\u00e9rabilit\u00e9s pour environnements isol\u00e9s**
{: .fs-6 .fw-300 }

---

## \ud83c\udfaf **\u00c0 quoi \u00e7a sert ?**

Air-Gapped CVEs permet aux prestataires informatiques de :

- \u2705 **Inventorier** les \u00e9quipements clients (serveurs, NAS, PC, cam\u00e9ras, etc.)
- \u2705 **Corr\u00e9ler automatiquement** les CVE NVD avec vos assets
- \u2705 **Analyser** les vuln\u00e9rabilit\u00e9s avec Mistral AI (contexte air-gap)
- \u2705 **Prioriser** les actions correctives par client/site

**Particularit\u00e9** : Fonctionne **sans agent** chez le client. Toutes les donn\u00e9es sont saisies manuellement ou import\u00e9es.

---

## \ud83d\udd12 **Contrainte Air-Gap**

Les environnements clients sont **physiquement isol\u00e9s d'Internet**. Impact sur le scoring :

- \u274c **P\u00e9nalis\u00e9** : CVE exploitable via Internet (`AV:N`)
- \u2705 **Bonifi\u00e9** : CVE exploitable en local (`AV:L`) ou physiquement (`AV:P`)

---

## \ud83c\udfd7\ufe0f **Architecture**

```
Raspberry Pi 5 / Ubuntu Server
\u251c\u2500\u2500 MariaDB 11.x    \u2192 Base de donn\u00e9es
\u251c\u2500\u2500 FastAPI         \u2192 API REST
\u251c\u2500\u2500 Scripts Python  \u2192 Corr\u00e9lation + Mistral AI
\u2514\u2500\u2500 Frontend HTML   \u2192 Interface web
```

---

## \ud83d\udcda **Documentation**

| Section | Description |
|---------|-------------|
| [\ud83d\udce5 Installation & Configuration]({{ site.baseurl }}/installation-configuration) | D\u00e9ploiement et configuration |
| [\ud83d\uddc3\ufe0f Base de donn\u00e9es]({{ site.baseurl }}/database) | Tables principales |
| [\u26a1 Corr\u00e9lation]({{ site.baseurl }}/correlation) | Comment \u00e7a marche |
| [\ud83c\udfaf Guides]({{ site.baseurl }}/guides) | Workflows pratiques |
| [\ud83d\udda5\ufe0f Interface]({{ site.baseurl }}/ui) | Utilisation quotidienne |
| [\ud83d\udd0c API]({{ site.baseurl }}/api) | R\u00e9f\u00e9rence technique |
