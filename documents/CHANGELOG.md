# Changelog - Asset Manager

## 2026-03-06 - Améliorations majeures

### 🎯 Page Documents
- ✅ Nouvelle page web `/ui/documents.html` pour consulter et télécharger les rapports PDF
- ✅ Interface moderne avec tri par date, taille des fichiers, et aperçu
- ✅ API REST complète pour gérer les documents (`/api/documents`)
- ✅ Téléchargement et prévisualisation des PDFs depuis le navigateur

### 📊 Rapports PDF améliorés
- ✅ **2 types de rapports** générés automatiquement :
  - **Synthèse** : document court (2-10 pages) avec uniquement les vulnérabilités critiques/hautes
  - **Rapport complet** : document détaillé (20-200 pages) avec toutes les vulnérabilités
- ✅ Organisation hiérarchique : Client → Site → Asset
- ✅ Noms de fichiers avec timestamp pour éviter les écrasements
- ✅ Sauvegarde automatique dans `/opt/asset-manager/documents/`

### 🚀 Performances et verbosité optimisées

#### Avant (trop verbeux)
```
2026-03-06 14:47:08,892 [INFO] [correlate:111] ======================================================================
2026-03-06 14:47:08,892 [INFO] [correlate:112] DÉBUT DE LA CORRÉLATION CVE
2026-03-06 14:47:08,892 [INFO] [correlate:113] ======================================================================
2026-03-06 14:47:08,892 [DEBUG] [correlate:114] Mode dry-run: False
2026-03-06 14:47:08,892 [DEBUG] [correlate:116] Connexion à la base de données...
2026-03-06 14:47:08,892 [DEBUG] [correlate:117] Connexion établie
...
(Des centaines de lignes de logs DEBUG)
```

#### Après (barres de progression claires)
```
======================================================================
  CORRÉLATION CVE / ASSETS
======================================================================

Assets à analyser : 6

Corrélation CVE: 100%|████████████████| 6/6 [00:02<00:00] Serveur | +42 CVE | Total: 156 nouvelles

======================================================================
  ✅ Nouvelles corrélations : 156
  ⏭️  Doublons ignorés       : 89
======================================================================
```

### 🔧 Changements techniques

#### Logging
- Niveau de log réduit de `DEBUG` à `WARNING`
- Suppression de tous les logs verbeux inutiles
- Conservation uniquement des erreurs et warnings importants
- Format simplifié : `%(asctime)s [%(levelname)s] %(message)s`

#### Affichage
- Toutes les fonctions utilisent maintenant `tqdm` pour les barres de progression
- Affichage en temps réel des statistiques dans la barre
- Flush automatique de stdout pour compatibilité web
- Style cohérent inspiré de `download_nvd.py`

#### Cache intelligent
- ✅ Les corrélations déjà analysées ne sont **jamais réanalysées**
- ✅ Économie massive sur les appels API Mistral
- ✅ Vérification via `date_analyse IS NULL`
- ⚠️ Mode `--force` disponible si réanalyse nécessaire (coûteux)

### 📝 Nouvelles commandes

```bash
# Corrélation avec barre de progression
python scripts/correlate_and_analyze.py correlate

# Analyse (uniquement nouvelles CVE grâce au cache)
python scripts/correlate_and_analyze.py analyze

# Génération des 2 rapports PDF
python scripts/correlate_and_analyze.py report

# Pipeline complet en une commande
python scripts/correlate_and_analyze.py run-all
```

### 🎨 Exemple d'affichage

```
======================================================================
  ANALYSE MISTRAL AI
======================================================================

Mode : Analyse uniquement des nouvelles CVE (cache activé)
Corrélations à analyser : 42

Analyse IA: 100%|████████████| 42/42 [01:15<00:00] Serveur-Web | ✅ 35 | ❌ 7 | ⚠️ 0

======================================================================
  ✅ Confirmées      : 35
  ❌ Faux positifs   : 7
  ⚠️  Erreurs        : 0
======================================================================
```

### 📁 Structure des fichiers

```
/opt/asset-manager/
├── documents/                          # Nouveau répertoire
│   ├── README.md                       # Documentation
│   ├── CHANGELOG.md                    # Ce fichier
│   ├── synthese_vulnerabilites_*.pdf   # Synthèses générées
│   └── rapport_complet_*.pdf           # Rapports complets
├── ui/
│   └── documents.html                  # Nouvelle page Documents
├── routers/
│   └── documents.py                    # Nouveau routeur API
└── scripts/
    └── correlate_and_analyze.py        # Script optimisé
```

### 🔒 Sécurité

- Validation stricte des chemins de fichiers (protection directory traversal)
- Vérification que les fichiers sont bien dans le répertoire documents
- Seuls les fichiers PDF sont autorisés
- API REST avec gestion d'erreurs complète

### ⚡ Performances

- **Avant** : ~500 lignes de logs pour 6 assets
- **Après** : 1 barre de progression + résultat final
- **Cache** : 0 appel API si déjà analysé
- **Temps réel** : Affichage immédiat grâce au flush stdout

### 📚 Documentation

- README complet dans `/opt/asset-manager/documents/README.md`
- Exemples de commandes pour tous les cas d'usage
- Guide d'utilisation de la page web Documents
- Recommandations pour optimiser les coûts API

---

## Migration

Aucune migration nécessaire, tout est rétrocompatible ! 🎉

Les anciens rapports PDF continuent de fonctionner.
Les nouvelles fonctionnalités sont additives.
