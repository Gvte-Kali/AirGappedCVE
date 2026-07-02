#!/usr/bin/env python3
import os
import sys
import pymysql
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
DB_PORT = int(os.getenv("DB_PORT"))
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

# =============================================================================
# 🗃️ VÉRIFIER LA CONNEXION ROOT VIA SOCKET UNIX
# =============================================================================
print("\n🔌 Tentative de connexion à MariaDB (root via socket Unix)...")
try:
    conn = pymysql.connect(
        host="localhost",
        user="root",
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        ssl_disabled=True,
        unix_socket="/var/run/mysqld/mysqld.sock"
    )
    print("✅ Connexion root réussie via socket Unix.")
except pymysql.MySQLError as e:
    print(f"❌ Échec de la connexion root : {e}")
    print("   → Vérifiez que MariaDB est démarré (`sudo systemctl status mariadb`).")
    print("   → Vérifiez que l'utilisateur système a accès au socket Unix (`ls -l /var/run/mysqld/mysqld.sock`).")
    sys.exit(1)

# =============================================================================
# 🛠️ EXÉCUTER LES COMMANDES SQL (AVEC VÉRIFICATIONS)
# =============================================================================
try:
    cursor = conn.cursor()

    # 1. Créer la base de données
    print(f"\n📦 Création de la base '{DB_NAME}'...")
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
    print(f"✅ Base '{DB_NAME}' créée ou existante.")

    # 2. Créer l'utilisateur local
    print(f"\n👤 Création de l'utilisateur '{DB_USER}'@'localhost'...")
    cursor.execute(f"CREATE USER IF NOT EXISTS '{DB_USER}'@'localhost' IDENTIFIED BY '{DB_PASSWORD}';")
    print(f"✅ Utilisateur '{DB_USER}'@'localhost' créé ou existant.")

    # 3. Créer l'utilisateur distant
    print(f"\n🌍 Création de l'utilisateur '{DB_USER}'@'%'...")
    cursor.execute(f"CREATE USER IF NOT EXISTS '{DB_USER}'@'%' IDENTIFIED BY '{DB_PASSWORD}';")
    print(f"✅ Utilisateur '{DB_USER}'@'%' créé ou existant.")

    # 4. Donner les permissions
    print(f"\n🔑 Attribution des permissions sur '{DB_NAME}'...")
    cursor.execute(f"GRANT ALL PRIVILEGES ON `{DB_NAME}`.* TO '{DB_USER}'@'localhost' WITH GRANT OPTION;")
    cursor.execute(f"GRANT ALL PRIVILEGES ON `{DB_NAME}`.* TO '{DB_USER}'@'%' WITH GRANT OPTION;")
    cursor.execute("FLUSH PRIVILEGES;")
    print(f"✅ Permissions attribuées à '{DB_USER}'.")

    conn.commit()
    print("\n🎉 Configuration terminée avec succès !")

except pymysql.MySQLError as e:
    conn.rollback()
    print(f"\n❌ Erreur SQL : {e}")
    sys.exit(1)
except Exception as e:
    conn.rollback()
    print(f"\n❌ Erreur inattendue : {e}")
    sys.exit(1)
finally:
    if 'conn' in locals() and conn.open:
        conn.close()
        print("\n🔌 Connexion fermée.")

# =============================================================================
# ✅ VÉRIFIER LA CONNEXION AVEC L'UTILISATEUR CRÉÉ
# =============================================================================
print(f"\n🔍 Vérification de la connexion avec '{DB_USER}'...")
try:
    test_conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
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
    print("   → Vérifiez DB_USER, DB_PASSWORD, DB_NAME et DB_HOST dans votre .env.")
    sys.exit(1)