from dotenv import load_dotenv
import os
import psycopg2
from pathlib import Path

path_to_dotenv = os.path.join('.env', '.env')
load_dotenv(path_to_dotenv)

# Access variables
database = os.getenv('DB_NAME')
host = os.getenv('DB_HOST')
password = os.getenv('DB_PASSWORD')
user = os.getenv('DB_USER')
port = os.getenv('DB_PORT')

# Validation (moved BEFORE connection attempt)
if not all([database, host, password, user, port]):
    raise ValueError("Missing required database environment variables")

try:
    # Create connection
    conn = psycopg2.connect(
        host=host,
        database=database,
        password=password,
        user=user,
        port=port
    )

    # Test connection
    cur = conn.cursor()
    cur.execute("SELECT version();")
    print("PostgreSQL version:", cur.fetchone())

    # List databases (corrected syntax)
    cur.execute("SELECT datname FROM pg_database;")
    print("\nDatabases:")
    for row in cur.fetchall():
        print(f"  - {row[0]}")

    cur.close()
    conn.close()

except psycopg2.OperationalError as e:
    print(f"Connection failed: {e}")
