---
title: Synchronisation NVD
parent: Guides opérationnels
nav_order: 7
---

# 🔄 Synchronisation NVD

**Mise à jour du référentiel CVE/CWE local**

---

## 🎯 **Principe**

Le moteur de corrélation travaille sur une **copie locale** de la base NVD.

- ✅ **Avantage** : Pas de dépendance à Internet pour la corrélation
- ⚠️ **Contrainte** : Nécessite une synchronisation régulière

---

## 📥 **Scripts de synchronisation**

### Script principal

```bash
# Télécharger et importer les dernières CVE
python3 scripts/download_nvd.py
```

**Options** :
```bash
# Synchronisation complète (longue)
python3 scripts/download_nvd.py --full

# Synchronisation incrémentale (rapide)
python3 scripts/download_nvd.py --incremental

# Depuis une date spécifique
python3 scripts/download_nvd.py --since 2024-01-01

# Limiter aux vendors spécifiques
python3 scripts/download_nvd.py --vendors microsoft,synology,fortinet
```

---

## 📊 **État de la base**

```sql
-- Nombre total de CVE
SELECT COUNT(*) as total FROM cve;
-- Résultat : ~932 000 CVE

-- CVE par vendor (top 10)
SELECT fabricant, COUNT(*) as nb
FROM cve
GROUP BY fabricant
ORDER BY nb DESC
LIMIT 10;

-- CVE récentes (30 derniers jours)
SELECT COUNT(*) as nb_recentes
FROM cve
WHERE date_publication >= DATE_SUB(NOW(), INTERVAL 30 DAY);

-- Dernière CVE importée
SELECT cve_id, date_publication, updated_at
FROM cve
ORDER BY updated_at DESC
LIMIT 1;
```

---

## 🔍 **Vérifier la couverture d'un vendor**

Avant de lancer une corrélation sur un nouvel équipement :

```sql
-- CVE disponibles pour un vendor
SELECT COUNT(*) as nb_cve, fabricant
FROM cve
WHERE fabricant = 'synology'
GROUP BY fabricant;

-- CVE par produit pour un vendor
SELECT produit, COUNT(*) as nb
FROM cve
WHERE fabricant = 'synology'
GROUP BY produit
ORDER BY nb DESC;
```

---

## ⚙️ **Configuration**

Dans `scripts/config.yml` :

```yaml
nvd:
  data_dir: "data/nvd"          # Répertoire de stockage
  raw_dir: "data/nvd/raw"      # Fichiers JSON bruts
  processed_dir: "data/nvd/processed"  # Fichiers traités
  batch_size: 1000              # Taille des batches
  max_workers: 4               # Nombre de workers
  timeout: 30                  # Timeout requêtes HTTP
```

---

## 📅 **Planification**

### Synchronisation automatique (cron)

```bash
# Synchronisation incrémentale quotidienne à 2h
0 2 * * * /opt/asset-manager/venv/bin/python3 /opt/asset-manager/scripts/download_nvd.py --incremental

# Synchronisation complète hebdomadaire le dimanche à 3h
0 3 * * 0 /opt/asset-manager/venv/bin/python3 /opt/asset-manager/scripts/download_nvd.py --full
```

### Synchronisation manuelle

```bash
# Lancer une sync complète
sudo systemctl stop asset-manager
python3 scripts/download_nvd.py --full
sudo systemctl start asset-manager
```

---

## 💡 **Bonnes pratiques**

- ✅ **Synchroniser régulièrement** (quotidiennement pour les mises à jour incrémentales)
- ✅ **Vérifier les logs** après chaque synchronisation
- ✅ **Surveiller l'espace disque** (la base NVD complète fait ~10-15 Go)
- ❌ **Ne pas synchroniser pendant les heures de pointe**
- ❌ **Ne pas interrompre une synchronisation en cours**

---

## 🚨 **Dépannage**

### Problème : Aucune CVE trouvée pour un vendor

1. Vérifier l'orthographe du `nvd_vendor`
2. Vérifier que le vendor existe dans la base :
   ```sql
   SELECT COUNT(*) FROM cve WHERE fabricant = 'votre_vendor';
   ```
3. Synchroniser à nouveau :
   ```bash
   python3 scripts/download_nvd.py --vendors votre_vendor
   ```

### Problème : Synchronisation lente

- Augmenter `batch_size` dans `config.yml`
- Augmenter `max_workers` (mais pas au-delà du nombre de cœurs CPU)

### Problème : Espace disque insuffisant

- Nettoyer les fichiers temporaires :
  ```bash
  rm -rf data/nvd/raw/*
  ```
- Synchroniser par vendors spécifiques plutôt que tout le NVD
