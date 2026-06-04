---
title: Console Scripts
parent: Interface utilisateur
nav_order: 5
---

# 🎯 Console Scripts

**Lancer et surveiller les scripts Python depuis l'interface web** - Sans accès SSH.

**URL** : `/ui/console` (lien **Console** dans la navbar)

---

## 📜 **Scripts disponibles**

| Script | Description | Commande |
|--------|-------------|----------|
| **🔄 Corrélation** | Phase 1+2 uniquement | `correlate_and_analyze.py correlate` |
| **🤖 Analyse Mistral** | Phase 3 uniquement | `correlate_and_analyze.py analyze` |
| **⚡ Pipeline complet** | Phases 1+2+3 | `correlate_and_analyze.py run-all` |

⚠️ **Mêmes scripts accessibles** depuis la page Vulnérabilités (boutons en haut à droite).

---

## 📊 **Suivi de l'exécution**

### Barre de progression

- Barre animée pendant l'exécution
- **Progression simulée** (incréments de 5% toutes les 2 secondes)
- Le script Python ne remonte pas de pourcentage exact

### Logs en temps réel

- Affichage en temps réel dans une zone monospace
- Scroll automatique
- **Polling** : toutes les 2 secondes sur `/api/correlations/run-status`

### États de fin

| Résultat | Couleur barre | Déclencheur |
|----------|--------------|-------------|
| ✅ **Succès** | Verte | Message contient "succès" |
| ❌ **Erreur** | Rouge | Tout autre message de fin |

---

## 🚫 **Gestion des exécutions concurrentes**

- Un seul pipeline peut tourner à la fois
- Nouveau lancement → **HTTP 409** + message d'avertissement
- **Solution** : Attendre la fin de l'exécution en cours

---

## 📝 **Logs persistants**

Les logs sont aussi écrits dans `logs/FastAPI.log` côté serveur.

```bash
# Voir les logs en temps réel
tail -f logs/FastAPI.log

# En production (systemd)
sudo journalctl -u asset-manager -f
```

---

## 💡 **Bonnes pratiques**

- ✅ **Lancer le pipeline complet** la nuit pour les gros inventaires
- ✅ **Vérifier les logs** après chaque exécution
- ✅ **Utiliser les filtres** avant de lancer une analyse Mistral ciblée
- ❌ **Ne pas lancer plusieurs pipelines** en parallèle
- ❌ **Ne pas interrompre** une exécution en cours (attendre la fin)
