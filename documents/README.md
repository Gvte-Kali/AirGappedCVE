# Répertoire Documents

Ce répertoire contient les rapports PDF générés automatiquement par le système de gestion des vulnérabilités.

## Types de rapports

### 1. Synthèse des vulnérabilités (`synthese_vulnerabilites_*.pdf`)

**Document court et actionnable** destiné aux décideurs et équipes opérationnelles.

**Contenu :**
- Statistiques globales (nombre total, répartition par priorité, exploitabilité air-gap)
- Liste synthétique des vulnérabilités **critiques et hautes uniquement**
- Format tableau compact avec : CVE ID, Client, Site, Asset, Priorité, Score, Recommandation courte
- Idéal pour : réunions de suivi, priorisation des actions, vue d'ensemble rapide

**Taille moyenne :** 2-10 pages selon le nombre de vulnérabilités critiques/hautes

---

### 2. Rapport complet (`rapport_complet_*.pdf`)

**Document détaillé** destiné aux équipes techniques et auditeurs.

**Contenu :**
- Statistiques globales identiques à la synthèse
- **Toutes les vulnérabilités** (critique, haute, moyenne, basse)
- Organisation hiérarchique : Client → Site → Asset
- Pour chaque vulnérabilité :
  - Fiche complète de l'asset (type, OS, firmware, criticité)
  - Description complète de la CVE
  - Vecteur d'attaque CVSS
  - Analyse d'exploitabilité en environnement air-gapped
  - Risque réel contextuel
  - Analyse détaillée par Mistral AI
  - Recommandations techniques complètes
- Idéal pour : investigations techniques, conformité, documentation d'audit

**Taille moyenne :** 20-200 pages selon le nombre total de vulnérabilités

---

## Génération des rapports

### Commande de base

```bash
python scripts/correlate_and_analyze.py report
```

Les fichiers seront générés dans `/opt/asset-manager/documents/` avec un timestamp automatique.

### Options disponibles

```bash
# Filtrer par client spécifique
python scripts/correlate_and_analyze.py report --client-id 1

# Filtrer par asset spécifique
python scripts/correlate_and_analyze.py report --asset-id 5

# Changer le répertoire de sortie
python scripts/correlate_and_analyze.py report --output-dir /chemin/custom

# Filtrer par score minimum
python scripts/correlate_and_analyze.py report --min-score 7.0

# Filtrer par statuts (par défaut : confirme,mitige)
python scripts/correlate_and_analyze.py report --statuts "confirme,mitige,nouveau"
```

### Pipeline complet automatique

```bash
# Exécute : corrélation + analyse Mistral + génération des 2 rapports
python scripts/correlate_and_analyze.py run-all
```

---

## Accès via l'interface web

Les rapports sont accessibles depuis l'interface web à l'adresse :

**http://votre-serveur/ui/documents.html**

Fonctionnalités disponibles :
- 📊 Liste de tous les rapports générés
- ⬇️ Téléchargement direct des PDFs
- 👁️ Aperçu dans le navigateur
- 📅 Tri par date de création
- 📦 Affichage de la taille des fichiers

---

## Gestion automatique

- **Format des noms :** `[type]_[date]_[heure].pdf`
- **Exemple :** `synthese_vulnerabilites_20260306_143052.pdf`
- **Pas de limite :** Les anciens rapports ne sont pas supprimés automatiquement
- **Nettoyage manuel :** Vous pouvez supprimer manuellement les anciens fichiers

---

## Recommandations d'usage

### Pour les responsables sécurité
👉 Consultez la **synthèse** quotidiennement pour suivre les nouvelles vulnérabilités critiques/hautes

### Pour les équipes techniques
👉 Utilisez le **rapport complet** pour les détails d'implémentation et les correctifs

### Pour les audits
👉 Archivez les **rapports complets** avec horodatage pour historique de conformité

---

## Optimisation des coûts API

Le système implémente un **cache intelligent** :
- ✅ Les corrélations déjà analysées ne sont **jamais réanalysées** par défaut
- ✅ Économise les appels à l'API Mistral
- ✅ Seulement les **nouvelles** corrélations sont envoyées à Mistral

Pour forcer une réanalyse complète (coûteux en API) :
```bash
python scripts/correlate_and_analyze.py analyze --force
```

---

## Support

Pour toute question ou problème, consultez les logs du script :
```bash
python scripts/correlate_and_analyze.py [commande] 2>&1 | tee execution.log
```
