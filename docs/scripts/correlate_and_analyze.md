---
title: Logique de corrélation
nav_order: 2
parent: Scripts
---

# **correlate\_and\_analyze.py**

Pipeline complet de **corrélation CVE/asset** et **analyse contextuelle**.  
Le script suit une **architecture en 3 phases** :

1. **Détection brute** (SQL uniquement, sans IA)
2. **Pré-classification déterministe** (règles Python, sans IA)
3. **Validation Mistral** (IA contextuelle pour confirmation et ajustement)

---

## **Architecture détaillée**

### **Phase 1 — Détection brute**

**Objectif** : Identifier les corrélations potentielles entre les **CVE** et les **assets** en utilisant uniquement des requêtes SQL et des règles de matching.

#### **Logique**

- **Match obligatoire** : `cve.fabricant == asset.nvd_vendor`
- **Scoring version** : Comparaison des tokens communs entre les versions de la CVE et celles de l'asset (OS, firmware, BIOS).
- **Bonus produit** : Ajoute +0.5 au score si le produit de la CVE correspond suffisamment à celui de l'asset (sans être bloquant).

#### **Passes de corrélation**

1. **`vendor_match`** :
  - Détermine le `vendor` de la CVE à partir de l'asset (via `get_correlation_vendor`).
  - Filtre les CVE par `vendor` et applique un matching flou ou exact sur le produit.
  - Vérifie la compatibilité des versions (exacte ou par plage).

#### **Gestion des versions**

- **Match exact** : Si une version exacte de l'asset est dans les plages vulnérables de la CVE → corrélation **affirmée**.
- **Match flou** : Si des tokens communs sont détectés (ex: `2019` dans `Windows Server 2019` et `2019` dans la CVE) → corrélation **informatif**.
- **Rejet** : Si la version de l'asset est **hors plage** ou non concernée → rejet avec logging dans `correlation_rejects`.

---

### **Phase 2 — Pré-classification déterministe**

**Objectif** : Calculer un **score de pré-triage** (`score_pre_triage`) et une **priorité** (`priorite_pre_triage`) selon des règles objectives, **sans IA**.

#### **Critères de scoring**


| Critère                                | Impact sur le score | Exemple                            |
| -------------------------------------- | ------------------- | ---------------------------------- |
| **CVSS v3**                            | Score de base       | `CVSS 9.8` → `+9.8`                |
| **Vecteur réseau (AV:N)**              | Pénalité            | `-3.0` (moins critique en air-gap) |
| **Vecteur local/physique (AV:L/AV:P)** | Bonus               | `+0.5` (plus pertinent en air-gap) |
| **Version asset confirmée vulnérable** | Bonus               | `+1.0`                             |
| **Type de produit (OS/Firmware)**      | Bonus               | `+0.5`                             |
| **Criticité de l'asset**               | Bonus               | `+1.0` (si `critique` ou `élevé`)  |
| **CWE pertinent en air-gap**           | Bonus               | `+0.5` (ex: `CWE-269`, `CWE-78`)   |
| **Type de vulnérabilité**              | Ajustement          | `+1.5` (RCE) à `-5.0` (XSS/CSRF)   |


#### **Priorité calculée**


| Score final | Priorité     |
| ----------- | ------------ |
| ≥ 9.0       | **Critique** |
| ≥ 7.0       | **Haute**    |
| ≥ 4.0       | **Moyenne**  |
| &lt; 4.0    | **Basse**    |


---

### **Phase 3 — Validation Mistral**

**Objectif** : **Valider ou infirmer** les corrélations via l'API Mistral, avec ajustement du score et du verdict.

#### **Fonctionnement**

- **Prompt système** : Contexte air-gap (accès physique contrôlé, pas d'accès réseau).
- **Prompt utilisateur** : Informations détaillées sur l'asset et la CVE (nom, type, versions, CVSS, description, etc.).

#### **Réponse attendue**

```json
{
  "verdict": "patcher" | "informatif" | "faux_positif",
  "ajustement_score": -2.0 à +2.0,
  "exploitable_air_gap": true | false | null,
  "justification": "1-2 phrases max",
  "recommandation": "Action concrète"
}
```

#### **Verdicts possibles**


| Verdict        | Statut en base | Description                               |
| -------------- | -------------- | ----------------------------------------- |
| `patcher`      | `confirme`     | L'asset est vulnérable, patch nécessaire. |
| `informatif`   | `informatif`   | Pertinent mais pas urgent (à surveiller). |
| `faux_positif` | `faux_positif` | Ne concerne pas cet asset.                |


#### **Score final**

- **Formule** : `score_final = score_pre_triage + ajustement_score` (clampé entre 0 et 10).
- **Priorité finale** : Recalculée à partir du `score_final` (mêmes seuils que la Phase 2).

---

## **Commandes disponibles**

### **`correlate`**

**Phase 1 + 2** : Détection brute + pré-classification.

```bash
python correlate_and_analyze.py correlate [--dry-run] [--verbose]
```


| Option      | Description                                                                   |
| ----------- | ----------------------------------------------------------------------------- |
| `--dry-run` | Affiche les résultats sans insérer en base.                                   |
| `--verbose` | Affiche les détails par asset (stratégie de corrélation, CVE matchées, etc.). |


#### **Sortie**

- Nombre de **nouvelles corrélations** insertées.
- Nombre de **mises à jour** (si une corrélation existante est améliorée par une passe plus précise).
- Nombre de **rejets** (CVE hors plage de version ou non pertinentes).

---

### **`analyze`**

**Phase 3** : Validation par Mistral.

```bash
python correlate_and_analyze.py analyze [--batch-max N] [--asset-id ID] [--force]
```


| Option          | Description                                                             |
| --------------- | ----------------------------------------------------------------------- |
| `--batch-max N` | Limite le nombre de CVE à analyser (par défaut : illimité).             |
| `--asset-id ID` | Analyse uniquement les corrélations d'un asset spécifique.              |
| `--force`       | Réanalyse **toutes** les corrélations (y compris celles déjà traitées). |


#### **Comportement**

- Traite les corrélations par **`score_pre_triage DESC`** (priorité aux plus critiques).
- Met à jour le statut en `en_analyse` pendant le traitement.
- **Délai entre requêtes** : Configurable via `MISTRAL_DELAY` (défaut : 1.5s).
- **Gestion des erreurs** : Reprend automatiquement en cas de rate limit (retry exponentiel).

#### **Sortie**

- Nombre de corrélations **confirmées** (`patcher`).
- Nombre de corrélations **informatives**.
- Nombre de **faux positifs**.
- Nombre d'**erreurs** (ex: timeout Mistral).

---

## **Configuration**

### **Fichiers de configuration**
- __Ces paramètres clés sont modifiables dans la page web paramètres__


| Fichier          | Description                                                            |
| ---------------- | ---------------------------------------------------------------------- |
| `config.yml`     | Paramètres généraux (seuils CVSS, dates, délais Mistral, etc.).        |
| `vuln_types.yml` | Définition des **types de vulnérabilités** (CWE, mots-clés, priorité). |
| `.env`           | Variables d'environnement (clé API Mistral, accès BDD).                |


---

### **Variables d'environnement**


| Variable          | Description                                         |
| ----------------- | --------------------------------------------------- |
| `MISTRAL_API_KEY` | Clé API pour Mistral (obligatoire pour la Phase 3). |
| `DB_HOST`         | Hôte de la base de données MariaDB.                 |
| `DB_USER`         | Utilisateur de la base de données.                  |
| `DB_PASSWORD`     | Mot de passe de la base de données.                 |
| `DB_NAME`         | Nom de la base de données.                          |


---

## **Logique de corrélation avancée**

### **Détection du vendor CVE**

Le script détermine le `vendor` de la CVE à partir de l'asset selon 4 stratégies (configurables via `equipment_types.vendor_source`) :


| Stratégie        | Source                                                    | Fallback                                        |
| ---------------- | --------------------------------------------------------- | ----------------------------------------------- |
| `os_fk`          | Vendor depuis la FK `os_version_id`                       | Détection textuelle dans `systeme_exploitation` |
| `fw_fk`          | Vendor depuis la FK `fw_version_id`                       | Vendor matériel (`nvd_vendor`)                  |
| `materiel`       | Vendor matériel direct                                    | FK `fw_version_id` si disponible                |
| `detection_auto` | Essaye `os_fk` → `fw_fk` → détection OS → vendor matériel | Aucun                                           |


### **Matching des versions**

- **Tokens extraits** :
  - Pour l'asset : `version_os`, `version_firmware`, `version_bios`, `systeme_exploitation`.
  - Pour la CVE : `versions_affectees` (JSON), `produit`, `description`.
- **Comparaison** : Utilise `common_chars_count()` pour compter les caractères alphanumériques communs.
- **Seuil minimal** : Configurable via `version_match_min_chars` (défaut : 4).

### **Gestion des plages de versions**

- **Version exacte** : `version_exact` dans la CVE → comparaison directe.
- **Plages** : Vérifie si la version de l'asset est dans `version_start_including`/`version_end_excluding`, etc.
- **Wildcard (`-`)** : Considéré comme vulnérable si aucune autre plage n'est précisée.

---

## **Fichiers de logs**

- **`logs/correlate_and_analyze.log`** : Logs complets du script (corrélation + analyse).
- **`logs/correlation_rejects.log`** : Détails des rejets (faux négatifs potentiels).