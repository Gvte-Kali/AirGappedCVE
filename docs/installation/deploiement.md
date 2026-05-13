---
title: Déploiement systemd
parent: Installation & Déploiement
nav_order: 4
---

# Déploiement systemd
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Principe

En production sur votre machine, FastAPI tourne comme un service systemd. Cela garantit :
- Le démarrage automatique au boot
- Le redémarrage automatique en cas de crash
- La gestion des logs via `journalctl`

---

## Créer le fichier de service

```bash
sudo nano /etc/systemd/system/asset-manager.service
```

Contenu du fichier :

```ini
[Unit]
Description=Asset & Vulnerability Manager — FastAPI
After=network.target mariadb.service
Requires=mariadb.service

[Service]
Type=simple
User=votre_utilisateur
Group=votre_utilisateur
WorkingDirectory=/opt/asset-manager
Environment="PATH=/opt/asset-manager/venv/bin"
ExecStart=/opt/asset-manager/venv/bin/uvicorn main:app \
    --host 0.0.0.0 \
    --port 3000 \
    --workers 2
Restart=on-failure
RestartSec=5s

# Logs
StandardOutput=journal
StandardError=journal
SyslogIdentifier=asset-manager

[Install]
WantedBy=multi-user.target
```

{: .note }
- Remplacer `votre_utilisateur` par le nom de votre utilisateur système. 
- Le `WorkingDirectory` doit pointer vers le répertoire du projet.

---

## Activer et démarrer le service

```bash
# Recharger la configuration systemd
sudo systemctl daemon-reload

# Activer le démarrage automatique au boot
sudo systemctl enable asset-manager

# Démarrer le service
sudo systemctl start asset-manager

# Vérifier le statut
sudo systemctl status asset-manager
```

---

## Commandes de gestion

```bash
# Démarrer
sudo systemctl start asset-manager

# Arrêter
sudo systemctl stop asset-manager

# Redémarrer
sudo systemctl restart asset-manager

# Recharger sans coupure (si supporté)
sudo systemctl reload asset-manager

# Voir les logs en temps réel
sudo journalctl -u asset-manager -f

# Voir les 50 dernières lignes de logs
sudo journalctl -u asset-manager -n 50 --no-pager
```

---

## Diagnostiquer les erreurs courantes

### `status=217/USER` — Utilisateur introuvable

```
Main process exited, code=exited, status=217/USER
```

**Cause :** Le champ `User=` dans le fichier `.service` référence un utilisateur qui n'existe pas.

**Solution :**
```bash
# Vérifier que l'utilisateur existe
id votre_utilisateur

# Corriger le fichier .service si nécessaire
sudo nano /etc/systemd/system/asset-manager.service
sudo systemctl daemon-reload
sudo systemctl restart asset-manager
```

### Erreur de module Python introuvable

```
ModuleNotFoundError: No module named 'fastapi'
```

**Cause :** Le service ne trouve pas le venv Python.

**Solution :** Vérifier que `Environment="PATH=/opt/asset-manager/venv/bin"` est bien présent dans le `.service` et que le venv existe :

```bash
ls /opt/asset-manager/venv/bin/uvicorn
```

### Erreur de connexion MariaDB

```
pymysql.err.OperationalError: (2003, "Can't connect to MySQL server")
```

**Cause :** MariaDB n'est pas démarré ou les credentials `.env` sont incorrects.

**Solution :**
```bash
sudo systemctl status mariadb
sudo systemctl start mariadb

# Vérifier le .env
cat /opt/asset-manager/.env
```

---

## Gestion des scripts Python

Les scripts de corrélation (`correlate_and_analyze.py`) sont actuellement lancés **manuellement** depuis l'interface web ou en ligne de commande.

```bash
# Depuis le répertoire du projet, venv activé
cd /opt/asset-manager
source venv/bin/activate

# Lancer la corrélation uniquement
python3 scripts/correlate_and_analyze.py correlate

# Lancer l'analyse Mistral uniquement
python3 scripts/correlate_and_analyze.py analyze

# Lancer le pipeline complet
python3 scripts/correlate_and_analyze.py run-all
```

{: .note }
La planification automatique via Cron n'est pas encore configurée. Elle sera documentée dans une prochaine version.

---

## Mise à jour du système

```bash
# Arrêter le service
sudo systemctl stop asset-manager

# Récupérer les mises à jour
cd /opt/asset-manager
git pull

# Mettre à jour les dépendances si requirements.txt a changé
source venv/bin/activate
pip install -r requirements.txt

# Appliquer les migrations SQL si le schéma a évolué
# (voir les notes de version pour les commandes ALTER TABLE)

# Redémarrer le service
sudo systemctl start asset-manager
sudo systemctl status asset-manager
```
