---
title: Déploiement systemd
parent: Installation & Déploiement
nav_order: 4
---

# Déploiement systemd

**Service FastAPI en production**

---

## 🎯 **Pourquoi systemd ?**

- ✅ Démarrage automatique au boot
- ✅ Redémarrage automatique en cas de crash
- ✅ Gestion des logs via `journalctl`

---

## 📝 **Créer le service**

```bash
sudo nano /etc/systemd/system/asset-manager.service
```

**Contenu** (adapter `User` et `WorkingDirectory`) :

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
StandardOutput=journal
StandardError=journal
SyslogIdentifier=asset-manager

[Install]
WantedBy=multi-user.target
```

---

## 🚀 **Gestion du service**

```bash
# Recharger systemd
sudo systemctl daemon-reload

# Activer (démarrage auto au boot)
sudo systemctl enable asset-manager

# Démarrer/Arrêter/Redémarrer
sudo systemctl start asset-manager
sudo systemctl stop asset-manager
sudo systemctl restart asset-manager

# Vérifier le statut
sudo systemctl status asset-manager
```

---

## 📊 **Logs**

```bash
# Voir les logs
sudo journalctl -u asset-manager -f

# Filtrer par date
sudo journalctl -u asset-manager --since "2024-01-01"

# Voir les erreurs
sudo journalctl -u asset-manager -p err
```

---

## 🔄 **Mise à jour**

```bash
# Après modification du code
sudo systemctl restart asset-manager
```
