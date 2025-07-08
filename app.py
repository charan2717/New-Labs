from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from datetime import datetime
import markdown
from markupsafe import Markup
import requests
import os

# === Load Environment ===
load_dotenv()

# === Flask App Setup ===
app = Flask(__name__)
app.secret_key = 'newlabs'
app.config['SESSION_COOKIE_SECURE'] = False  # Only for local testing
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///users.db"
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# === Together API Configuration ===
API_KEY = "5a812dabc044d8d9f0b7805aab68eb90929c766983f930682c22f164563bb656"
API_URL = "https://api.together.xyz/v1/chat/completions"

# === Google OAuth Blueprint ===
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID", "266333494053-iin2ss3vsdaklo4is318laa21ecbd03v.apps.googleusercontent.com"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", "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"),
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_url="/login/google/authorized"
)
app.register_blueprint(google_bp, url_prefix="/login")

# === Database Models ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text)
    response = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# === Routes ===
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('chat'))
        flash('Invalid Credentials')
    return render_template('login.html')

@app.route("/login/google/authorized")
def google_authorized():
    if not google.authorized:
        flash("Google login failed.")
        return redirect(url_for("login"))

    try:
        resp = google.get("/oauth2/v2/userinfo")
        if not resp.ok:
            flash("Failed to fetch user info from Google.")
            return redirect(url_for("login"))

        user_info = resp.json()
        email = user_info.get("email")

        if not email:
            flash("Email not returned by Google.")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, password=generate_password_hash("google-oauth-user"))
            db.session.add(user)
            db.session.commit()

        session["user_id"] = user.id
        return redirect(url_for("chat"))

    except Exception as e:
        flash(f"OAuth error: {str(e)}")
        return redirect(url_for("login"))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('User already exists')
        else:
            hashed = generate_password_hash(password)
            new_user = User(email=email, password=hashed)
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful. Please login.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_message = request.form.get('prompt', '')
        file = request.files.get('file')

        if file and file.filename:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            user_message += f"\n[User uploaded file: {filename}]"

        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "model": "meta-llama/Llama-3-70b-chat-hf",
            "messages": [{"role": "user", "content": user_message}]
        }

        try:
            response = requests.post(API_URL, json=data, headers=headers)
            if response.status_code == 200:
                gpt_reply = response.json()["choices"][0]["message"]["content"]
            else:
                gpt_reply = f"Error: {response.status_code} - {response.text}"
        except Exception as e:
            gpt_reply = f"Error: {str(e)}"

        new_chat = Chat(user_id=session['user_id'], message=user_message, response=gpt_reply)
        db.session.add(new_chat)
        db.session.commit()

    chat_history = Chat.query.filter_by(user_id=session['user_id']).order_by(Chat.timestamp).all()
    for chat in chat_history:
        chat.response = Markup(markdown.markdown(chat.response, extensions=["fenced_code", "codehilite"]))

    return render_template('chat.html', chat_history=chat_history)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# === App Start ===
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
