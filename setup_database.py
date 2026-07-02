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
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_FILE = os.path.join(PROJECT_DIR, "sql", "schema.sql")

# =============================================================================
# 🛠️ CRÉER LA BASE ET L'UTILISATEUR VIA sudo mysql
# =============================================================================
print("\n🛠️ Création de la base et de l'utilisateur...")
commands = [
    f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;",
    f"CREATE USER IF NOT EXISTS '{DB_USER}'@'localhost' IDENTIFIED BY '{DB_PASSWORD}';",
    f"CREATE USER IF NOT EXISTS '{DB_USER}'@'%' IDENTIFIED BY '{DB_PASSWORD}';",
    f"GRANT ALL PRIVILEGES ON `{DB_NAME}`.* TO '{DB_USER}'@'localhost' WITH GRANT OPTION;",
    f"GRANT ALL PRIVILEGES ON `{DB_NAME}`.* TO '{DB_USER}'@'%' WITH GRANT OPTION;",
    "FLUSH PRIVILEGES;"
]

for cmd in commands:
    try:
        subprocess.run(
            ["sudo", "mysql", "-e", cmd],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(f"   ✅ {cmd.split()[0]}...")
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Échec : {e.stderr.strip()}")
        sys.exit(1)

# =============================================================================
# 📥 IMPORTER LE SCHÉMA SQL (SI LE FICHIER EXISTE)
# =============================================================================
if os.path.exists(SCHEMA_FILE):
    print(f"\n📥 Import du schéma SQL depuis {SCHEMA_FILE}...")
    try:
        subprocess.run(
            ["sudo", "mysql", f"{DB_NAME}", f"< {SCHEMA_FILE}"],
            check=True,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print("   ✅ Schéma importé avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Échec de l'import du schéma : {e.stderr.strip()}")
        print(f"   → Vérifiez que le fichier {SCHEMA_FILE} existe et est valide.")
        sys.exit(1)
else:
    print(f"\n⚠️  Fichier {SCHEMA_FILE} introuvable. Aucune table ne sera créée.")
    print("   → Exécutez 'asset-manager db import-schema' plus tard pour importer le schéma.")

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
    cursor = test_conn.cursor()
    cursor.execute("SHOW TABLES;")
    tables = cursor.fetchall()
    print(f"   ✅ Connexion réussie avec '{DB_USER}' sur '{DB_NAME}' !")
    if tables:
        print(f"   Tables présentes : {', '.join([t[0] for t in tables])}")
    else:
        print("   ⚠️  Aucune table trouvée (le schéma n'a pas été importé).")
    test_conn.close()
except pymysql.MySQLError as e:
    print(f"   ❌ Échec de la connexion : {e}")
    sys.exit(1)
except ImportError:
    print("   ⚠️  pymysql non installé. Impossible de vérifier les tables.")
    print("   → Installez-le avec : pip install pymysql")

print("\n🎉 Configuration terminée avec succès !")