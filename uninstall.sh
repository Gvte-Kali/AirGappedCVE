#!/bin/bash

# Stoper mariaDB et désinstaller le service et ses dépendances
sudo systemctl stop mariadb
sudo apt purge -y mariadb-server mariadb-client mariadb-common
sudo apt autoremove -y
sudo rm -rf /etc/mysql/
sudo rm -rf /var/lib/mysql/
sudo rm -rf /var/log/mysql/

# Suppression du répertoire du projet, PATH, alias, logs et fichiers temporaires
sudo rm -rf /opt/asset-manager/
sudo rm -rf /tmp/asset-manager*
sudo rm -f /var/log/asset-manager*
sudo rm -f /etc/profile.d/asset-manager.sh


# Supprimer les services systemd

sudo systemctl stop asset-manager asset-manager-dev 2>/dev/null || true
sudo systemctl disable asset-manager asset-manager-dev 2>/dev/null || true
sudo rm -f /etc/systemd/system/asset-manager.service
sudo rm -f /etc/systemd/system/asset-manager-dev.service
sudo systemctl daemon-reload

echo "Désinstallation terminée. Veuillez redémarrer votre système pour finaliser la suppression des services."