#pip install flask flask-mysql flask-wtf flask-login werkzeug bcrypt

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
    password_bytes = password.encode('utf-8')  # Encode password to bytes
    salt = bcrypt.gensalt()  # Generate a salt
    hashed_password = bcrypt.hashpw(password_bytes, salt)  # Hash the password
    return hashed_password  # Return hashed password as bytes

# Function to check if entered password matches hashed password
def check_bcrypt_hash(password, hashed_password):
    password_bytes = password.encode('utf-8')  # Encode entered password to bytes
    return bcrypt.checkpw(password_bytes, hashed_password)  # Check if password matches hashed password

# BCrypt hashing function end

# Global variable for hash type
HASH_TYPE = 'bcrypt' # 'default','md5','bcrypt'


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if(HASH_TYPE == 'default'):
            hashed_password = generate_password_hash(password)

        if(HASH_TYPE == 'md5'):
            hashed_password = md5_hash(password)

        if(HASH_TYPE == 'bcrypt'):
            hashed_password = bcrypt_hash(password)

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
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

            if user and check_bcrypt_hash(password, user['password']):  # Verify the password
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
