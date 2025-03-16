import os

DB_CONFIG = {
    'MYSQL_HOST': 'localhost',
    'MYSQL_USER': 'root',
    'MYSQL_PASSWORD': '',
    'MYSQL_DB': 'flask_hashing_algo',
    'MYSQL_CURSORCLASS': 'DictCursor'
}

SECRET_KEY = os.urandom(24)  # For session security
