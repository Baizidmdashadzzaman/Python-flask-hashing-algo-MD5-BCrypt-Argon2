#pip install flask flask-mysql flask-wtf flask-login werkzeug bcrypt argon2-cffi

from flask import Flask, render_template, request, redirect, url_for, flash
from database import mysql, init_db
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash


# MD5 hashing function start
import hashlib
# MD5 hashing function end

# BCrypt hashing function start
import bcrypt
# BCrypt hashing function end

# Argon2 hashing function start
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
ph = PasswordHasher()
def argon2_hash(password):
    return ph.hash(password)
def check_argon2_hash(password, hashed_password):
    try:
        return ph.verify(hashed_password, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False
# Argon2 hashing function end

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
init_db(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    if user:
        return User(user['id'], user['username'], user['password'])
    return None


# MD5 hashing function start
def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()
# MD5 hashing function end

# BCrypt hashing function start
def bcrypt_hash(password):
    password_bytes = password.encode('utf-8')  
    salt = bcrypt.gensalt()                    
    hashed_password = bcrypt.hashpw(password_bytes, salt)  
    return hashed_password 
def check_bcrypt_hash(password, hashed_password):
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    password_bytes = password.encode('utf-8')  
    return bcrypt.checkpw(password_bytes, hashed_password)  
# BCrypt hashing function end

# Global variable for hash type
HASH_TYPE = 'argon2' # 'default','md5','bcrypt','argon2'


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if(HASH_TYPE == 'default'):
            hashed_password = generate_password_hash(password)
            type = 'default'

        if(HASH_TYPE == 'md5'):
            hashed_password = md5_hash(password)
            type = 'md5'

        if(HASH_TYPE == 'bcrypt'):
            hashed_password = bcrypt_hash(password)
            type = 'bcrypt'

        if(HASH_TYPE == 'argon2'):
            hashed_password = argon2_hash(password)
            type = 'argon2'

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username,hashed_password,type))
        mysql.connection.commit()
        cur.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if(HASH_TYPE == 'default'):
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()
        
            if user and check_password_hash(user['password'], password):
                login_user(User(user['id'], user['username'], user['password']))
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password", "danger")

        if(HASH_TYPE == 'md5'):
            hashed_password = md5_hash(password)

            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, hashed_password))
            user = cur.fetchone()
            cur.close()

            if user:
                login_user(User(user['id'], user['username'], user['password']))
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password", "danger")        

        if(HASH_TYPE == 'bcrypt'):
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()

            if user and check_bcrypt_hash(password, user['password']):  
                login_user(User(user['id'], user['username'], user['password']))
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password", "danger")

        if(HASH_TYPE == 'argon2'):
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()

            if user and check_argon2_hash(password, user['password']):
                login_user(User(user['id'], user['username'], user['password']))
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password", "danger")

    return render_template('login.html')




@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))



@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
