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
 | `AV:L` (Local) | ✅ Bonifié  | Exploitable localement |
 | `AV:P` (Physical) | ✅ Bonifié  | Exploitable physiquement |

---