import os
from dotenv import load_dotenv

load_dotenv()

print("DB_HOST:", os.getenv('DB_HOST'))
print("DB_NAME:", os.getenv('DB_NAME'))
print("DB_USER:", os.getenv('DB_USER'))
print("DB_PASSWORD:", os.getenv('DB_PASSWORD'))
print("DATABASE_URL exists:", bool(os.getenv('DATABASE_URL')))
