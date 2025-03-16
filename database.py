from flask_mysqldb import MySQL
from config import DB_CONFIG

mysql = MySQL()

def init_db(app):
    app.config.update(DB_CONFIG)
    mysql.init_app(app)
