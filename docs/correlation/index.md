---
title: Moteur de corrélation
nav_order: 5
has_children: true
---

# Moteur de corrélation CVE

Le moteur de corrélation est le cœur analytique du système. Il associe automatiquement les CVE du NVD aux assets inventoriés, en tenant compte du contexte air-gap.

## Architecture en 3 phases

```
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1 — Détection brute (Python, zéro IA)               │
│                                                             │
│  Pour chaque asset actif avec vendor_id :                   │
│    1. Déterminer le vendor NVD (os_fk / fw_fk / materiel)  │
│    2. Charger les CVE du vendor en cache                    │
│    3. Filtrer par produit NVD exact (FK) ou fuzzy           │
│    4. Vérifier le range de versions (is_version_affected)   │
│    5. Insérer la corrélation en base                        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  PHASE 2 — Pré-classification déterministe (Python, zéro IA)│
│                                                             │
│  Pour chaque corrélation insérée :                          │
│    1. Score de base = CVSS v3                               │
│    2. Pénalité si AV:N (réseau, moins critique en air-gap)  │
│    3. Bonus si AV:L / AV:P (local / physique)               │
│    4. Bonus si version affirmée, criticité élevée, CWE      │
│    5. Ajustement selon type d'attaque (vuln_types.yml)      │
│    → score_pre_triage + priorite_pre_triage                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  PHASE 3 — Validation Mistral AI (contextuelle)             │
│                                                             │
│  Pour chaque corrélation (statut=nouveau, passer_mistral=1) │
│    1. Construire le prompt avec contexte asset + CVE        │
│    2. Appeler l'API Mistral                                 │
│    3. Parser le verdict JSON                                │
│    4. Mettre à jour statut, score_contextuel, analyse       │
│    → verdict : patcher | informatif | faux_positif          │
└─────────────────────────────────────────────────────────────┘
```

## Fichier principal

Tout le moteur est dans un seul fichier :

```
scripts/correlate_and_analyze.py
```

Lancé via :
```bash
python3 scripts/correlate_and_analyze.py correlate   # Phase 1+2 uniquement
python3 scripts/correlate_and_analyze.py analyze     # Phase 3 uniquement
python3 scripts/correlate_and_analyze.py run-all     # Pipeline complet
```

## Pages

- [Vue d'ensemble]({{ site.baseurl }}/correlation/vue-ensemble) — flux détaillé bout en bout
- [Phase 1 — Détection brute]({{ site.baseurl }}/correlation/phase1-detection) — vendor match, filtre produit, fuzzy
- [Phase 2 — Pré-classification]({{ site.baseurl }}/correlation/phase2-pretriage) — scoring déterministe
- [Phase 3 — Analyse Mistral]({{ site.baseurl }}/correlation/phase3-mistral) — prompt, verdicts, ajustements
- [Comparaison de versions]({{ site.baseurl }}/correlation/versions) — `is_version_affected()`, notation NVD
- [Contrainte Air-Gap]({{ site.baseurl }}/correlation/air-gap) — impact sur le scoring
- [config.yml]({{ site.baseurl }}/correlation/config) — référence complète des paramètres
- [vuln_types.yml]({{ site.baseurl }}/correlation/vuln-types) — classification des types d'attaque
