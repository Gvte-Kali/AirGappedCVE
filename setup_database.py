#!/usr/bin/env python3
import os
import sys
import pymysql
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER", "avea")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "asset_vuln_manager")

def setup_database():
    try:
        # Connexion via socket Unix en tant que root (sans mot de passe)
        conn = pymysql.connect(
            host="localhost",  # Obligatoire pour le socket Unix
            user="root",       # Utilisateur système root
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            ssl_disabled=True,
            unix_socket="/var/run/mysqld/mysqld.sock"  # Chemin du socket Unix
        )

        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        cursor.execute(f"CREATE USER IF NOT EXISTS '{DB_USER}'@'localhost' IDENTIFIED BY '{DB_PASSWORD}';")
        cursor.execute(f"CREATE USER IF NOT EXISTS '{DB_USER}'@'%' IDENTIFIED BY '{DB_PASSWORD}';")
        cursor.execute(f"GRANT ALL PRIVILEGES ON `{DB_NAME}`.* TO '{DB_USER}'@'localhost' WITH GRANT OPTION;")
        cursor.execute(f"GRANT ALL PRIVILEGES ON `{DB_NAME}`.* TO '{DB_USER}'@'%' WITH GRANT OPTION;")
        cursor.execute("FLUSH PRIVILEGES;")

        conn.commit()
        print(f"✅ Base '{DB_NAME}' et utilisateur '{DB_USER}' créés avec succès.")

    except pymysql.MySQLError as e:
        print(f"❌ Erreur MySQL : {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erreur : {e}")
        sys.exit(1)
    finally:
        if 'conn' in locals() and conn.open:
            conn.close()

if __name__ == "__main__":
    setup_database()