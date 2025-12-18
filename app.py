from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from models import db, User, PasswordResetOTP
import random

# ----------------- HELPER -----------------
def generate_otp():
    return str(random.randint(100000, 999999))

# ----------------- CREATE APP -----------------
def create_app():
    app = Flask(__name__)

    # ---------------- CONFIG ----------------
    app.config['SECRET_KEY'] = 'replace-with-a-secure-random-secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ---------------- MAIL ----------------
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'akashsharma123@gmail.com'
    app.config['MAIL_PASSWORD'] = 'abcd efgh ijkl mnop'
    app.config['MAIL_DEFAULT_SENDER'] = 'akashsharma123@gmail.com'

    # ---------------- RATE LIMITER ----------------
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"]
    )

    # ---------------- EXTENSIONS ----------------
    mail = Mail(app)
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ---------------- HOME ----------------
    @app.route('/')
    def index():
        return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

    # ---------------- REGISTER ----------------
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            password2 = request.form['password2']

            if password != password2:
                flash("Passwords do not match", "danger")
                return redirect(url_for('register'))

            if User.query.filter_by(username=username).first():
                flash("Username already exists", "danger")
                return redirect(url_for('register'))

            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            flash("Registration successful", "success")
            return redirect(url_for('login'))

        return render_template('register.html')

    # ---------------- LOGIN (RATE LIMITED) ----------------
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def login():
        if request.method == 'POST':
            user = User.query.filter_by(username=request.form['username']).first()

            if user and user.check_password(request.form['password']):
                login_user(user)
                return redirect(url_for('dashboard'))

            flash("Invalid credentials", "danger")

        return render_template('login.html')

    # ---------------- DASHBOARD ----------------
    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html')

    # ---------------- TEST EMAIL ----------------
    @app.route('/test-email')
    def test_email():
        try:
            msg = Message(
                "Test Email from Flask",
                recipients=["yourgmail@gmail.com"],  # CHANGE
                body="Flask-Mail is working!"
            )
            mail.send(msg)
            return "✅ Email sent successfully"
        except Exception as e:
            return f"❌ Email failed: {e}"

    # ---------------- FORGOT PASSWORD (RATE LIMITED) ----------------
    @app.route('/forgot-password', methods=['GET', 'POST'])
    @limiter.limit("3 per 15 minutes")
    def forgot_password():
        if request.method == 'POST':
            email = request.form['email']
            user = User.query.filter_by(email=email).first()

            if user:
                raw_otp = generate_otp()
                hashed_otp = generate_password_hash(raw_otp)

                reset = PasswordResetOTP(
                    email=email,
                    otp=hashed_otp,
                    expires_at=datetime.utcnow() + timedelta(minutes=5)
                )
                db.session.add(reset)
                db.session.commit()

                msg = Message(
                    "Password Reset OTP",
                    recipients=[email],
                    body=f"Your OTP is {raw_otp}"
                )
                mail.send(msg)

            flash("If email exists, OTP sent", "info")
            return redirect(url_for('verify_otp'))

        return render_template('forgot_password.html')

    # ---------------- VERIFY OTP ----------------
    @app.route('/verify-otp', methods=['GET', 'POST'])
    def verify_otp():
        if request.method == 'POST':
            email = request.form['email']
            otp = request.form['otp']

            record = PasswordResetOTP.query.filter_by(email=email).first()

            if not record or not check_password_hash(record.otp, otp):
                flash("Invalid OTP", "danger")
                return redirect(url_for('verify_otp'))

            return redirect(url_for('reset_password', email=email))

        return render_template('verify_otp.html')

    # ---------------- RESET PASSWORD ----------------
    @app.route('/reset-password/<email>', methods=['GET', 'POST'])
    def reset_password(email):
        user = User.query.filter_by(email=email).first_or_404()

        if request.method == 'POST':
            user.set_password(request.form['password'])
            PasswordResetOTP.query.filter_by(email=email).delete()
            db.session.commit()

            flash("Password reset successful", "success")
            return redirect(url_for('login'))

        return render_template('reset_password.html')

    # ---------------- LOGOUT ----------------
    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('login'))

    return app


# ---------------- RUN ----------------
if __name__ == '__main__':
    create_app().run(debug=True)
