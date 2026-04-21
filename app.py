from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from flask_bcrypt import Bcrypt
import os
from functools import wraps
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

load_dotenv()

app = Flask(__name__)

# Secure Configuration
# Using environment variables for secure secret management
app.config["SECRET_KEY"] = os.getenv('FLASK_SECRET_KEY', 'super-secret-key-12345')
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv('DATABASE_URL', 'sqlite:///firstapp.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

# Task 1: Implement Security Headers
Talisman(app, content_security_policy=None, force_https=False)

# Task 2: Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Session Management Security (3. Session Management)
app.config["SESSION_COOKIE_SECURE"] = False  # Set to True in production with HTTPS. False for local HTTP dev.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db = SQLAlchemy(app)
csrf = CSRFProtect(app) # 3. CSRF Protection
bcrypt = Bcrypt(app)    # 5. Secure Password Storage

# Task 5: Role-Based Access Control (RBAC) - Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return FirstApp.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403) # Forbidden
        return f(*args, **kwargs)
    return decorated_function

class FirstApp(db.Model, UserMixin):
    sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fname = db.Column(db.String(200), nullable=False)
    lname = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False) # Hashed password column
    is_admin = db.Column(db.Boolean, default=False) # Task 5: RBAC
    
    def get_id(self):
        return str(self.sno)

    def __repr__(self):
        return f"{self.sno} - {self.fname}"

# 1. Secure Input Handling via WTForms
class UserRegistrationForm(FlaskForm):
    fname = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    lname = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    submit = SubmitField('Submit')

class UpdateForm(FlaskForm):
    fname = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    lname = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route("/", methods=["GET", "POST"])
def hello_world():
    form = UserRegistrationForm()
    
    if form.validate_on_submit():
        # Input is validated automatically by WTForms (1. Secure Input Handling)
        
        # 5. Secure Password Storage (Hashing)
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        # 2. Parameterized Queries (SQLAlchemy ORM handles this inherently)
        person = FirstApp(
            fname=form.fname.data, 
            lname=form.lname.data, 
            email=form.email.data,
            password=hashed_password
        )
        db.session.add(person)
        db.session.commit()
        return redirect(url_for("hello_world"))

    # SQLAlchemy inherent parameterization
    allpeople = FirstApp.query.all()
    return render_template("index.html", allpeople=allpeople, form=form)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # Task 2: Rate Limiting
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = FirstApp.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('hello_world'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('hello_world'))

# Task 3: Secure File Uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File uploaded successfully', 'success')
            return redirect(url_for('hello_world'))
    return render_template('upload.html')

@app.route("/admin/delete_user/<int:sno>", methods=["POST"])
@admin_required
def delete_user(sno):
    # Only users with is_admin=True can reach this line
    person = FirstApp.query.filter_by(sno=sno).first()
    if person:
        db.session.delete(person)
        db.session.commit()
    return redirect(url_for('hello_world'))


@app.route("/update/<int:sno>", methods=["GET", "POST"])
def update(sno):
    person = FirstApp.query.filter_by(sno=sno).first_or_404()
    form = UpdateForm(obj=person)

    if form.validate_on_submit():
        person.fname = form.fname.data
        person.lname = form.lname.data
        person.email = form.email.data
        db.session.commit()
        return redirect(url_for('hello_world'))

    return render_template("update.html", person=person, form=form)

# 4. Secure Error Handling
@app.errorhandler(404)
def page_not_found(e):
    # Avoid information disclosure by rendering a generic template
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
