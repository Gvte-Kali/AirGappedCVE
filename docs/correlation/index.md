---
title: Moteur de corrélation
nav_order: 5
has_children: true
---

# ⚡ Moteur de corrélation CVE

**Cœur analytique** - Associe automatiquement les CVE NVD aux assets, avec contexte air-gap.

---

## 🎯 **3 Phases**

```
PHASE 1 — Détection brute (Python)
├── Pour chaque asset actif avec vendor_id
├── Détermine le vendor NVD (os_fk / fw_fk / materiel)
├── Charge les CVE du vendor en cache
├── Filtre par produit et version
└── Insère la corrélation en base

PHASE 2 — Pré-classification (Python)
├── Score de base = CVSS v3
├── ❌ Pénalité si AV:N (réseau, moins critique en air-gap)
├── ✅ Bonus si AV:L / AV:P (local / physique)
├── ✅ Bonus si version affirmée, criticité élevée, CWE
└── → score_pre_triage + priorite_pre_triage

PHASE 3 — Validation Mistral AI (contextuelle)
├── Construire le prompt avec contexte asset + CVE
├── Appeler l'API Mistral
├── Parser le verdict JSON
└── → verdict : confirme | infirme | informatif | mitige
```

---

## 🚀 **Utilisation**

```bash
# Pipeline complet (Phases 1+2+3)
python3 scripts/correlate_and_analyze.py run-all

# Détection uniquement (Phases 1+2)
python3 scripts/correlate_and_analyze.py correlate

# Analyse Mistral uniquement (Phase 3)
python3 scripts/correlate_and_analyze.py analyze
```

---

## 📖 **Documentation**

- [🔍 Phase 1 — Détection]({{ site.baseurl }}/correlation/phase1-detection) — Vendor match, filtres
- [⚖️ Phase 2 — Scoring]({{ site.baseurl }}/correlation/phase2-pretriage) — Ajustements déterministes
- [🤖 Phase 3 — Mistral]({{ site.baseurl }}/correlation/phase3-mistral) — Analyse contextuelle
- [📊 Contrainte Air-Gap]({{ site.baseurl }}/correlation/air-gap) — Impact sur le scoring
- [⚙️ Configuration]({{ site.baseurl }}/correlation/config) — Paramètres du moteur
- [🏷️ Types de vulnérabilités]({{ site.baseurl }}/correlation/vuln-types) — Classification
