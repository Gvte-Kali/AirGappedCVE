#!/usr/bin/env python3
import os
import sys
import subprocess
from dotenv import load_dotenv

# =============================================================================
# 🔍 VÉRIFIER LE CHARGEMENT DU .ENV
# =============================================================================
env_path = os.path.join(os.path.dirname(__file__), ".env")
if not os.path.exists(env_path):
    print(f"❌ Fichier .env introuvable à : {env_path}")
    sys.exit(1)

load_dotenv(env_path)

# Afficher les variables chargées (pour débogage)
print("🔑 Variables chargées depuis .env :")
required_vars = ["DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME"]
missing_vars = []
for var in required_vars:
    value = os.getenv(var)
    if value is None:
        missing_vars.append(var)
        print(f"   ❌ {var} : NON DÉFINI")
    else:
        print(f"   ✅ {var} : {value if var != 'DB_PASSWORD' else '*****'}")

if missing_vars:
    print(f"\n❌ Variables manquantes : {', '.join(missing_vars)}")
    sys.exit(1)

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

# =============================================================================
# 🛠️ EXÉCUTER LES COMMANDES SQL VIA sudo mysql
# =============================================================================
commands = [
    f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;",
    f"CREATE USER IF NOT EXISTS '{DB_USER}'@'localhost' IDENTIFIED BY '{DB_PASSWORD}';",
    f"CREATE USER IF NOT EXISTS '{DB_USER}'@'%' IDENTIFIED BY '{DB_PASSWORD}';",
    f"GRANT ALL PRIVILEGES ON `{DB_NAME}`.* TO '{DB_USER}'@'localhost' WITH GRANT OPTION;",
    f"GRANT ALL PRIVILEGES ON `{DB_NAME}`.* TO '{DB_USER}'@'%' WITH GRANT OPTION;",
    "FLUSH PRIVILEGES;"
]

print("\n🔧 Exécution des commandes SQL via sudo mysql...")
for i, cmd in enumerate(commands, 1):
    print(f"\n{i}. Exécution : {cmd.split()[0]}...")
    try:
        result = subprocess.run(
            ["sudo", "mysql", "-e", cmd],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(f"   ✅ Succès.")
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Échec : {e.stderr.strip()}")
        sys.exit(1)

# =============================================================================
# ✅ VÉRIFIER LA CONNEXION AVEC L'UTILISATEUR CRÉÉ
# =============================================================================
print(f"\n🔍 Vérification de la connexion avec '{DB_USER}'...")
try:
    import pymysql
    test_conn = pymysql.connect(
        host=DB_HOST,
        port=int(DB_PORT),
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        ssl_disabled=True,
    )
    print(f"✅ Connexion réussie avec '{DB_USER}' sur '{DB_NAME}' !")
    test_conn.close()
except pymysql.MySQLError as e:
    print(f"❌ Échec de la connexion avec '{DB_USER}' : {e}")
    sys.exit(1)
except ImportError:
    print("❌ Le module pymysql n'est pas installé. Installez-le avec : pip install pymysql")
    sys.exit(1)

print("\n🎉 Configuration terminée avec succès !")