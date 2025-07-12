from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from forms import SignupForm, LoginForm
from flask_migrate import Migrate

# Initialize app and config
app = Flask(__name__)
app.config.from_object('config.Config')
app.config['UPLOAD_FOLDER'] = 'static/uploads'

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4'}

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ------------------------ MODELS ------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    materials = db.relationship('Material', backref='uploader', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    grade = db.Column(db.String(20), nullable=True)
    subject = db.Column(db.String(100), nullable=True)
    comments = db.relationship('Comment', backref='material_obj', lazy=True)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(50), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_positive = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    material_id = db.Column(db.Integer, db.ForeignKey('material.id'), nullable=False)

# ------------------------ LOGIN LOADER ------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------------ ROUTES ------------------------

@app.route('/')
def home():
    return render_template('welcome.html')

@app.route('/materials')
def materials():
    grade = request.args.get('grade')
    subject = request.args.get('subject')

    query = Material.query
    if grade:
        query = query.filter_by(grade=grade)
    if subject:
        query = query.filter_by(subject=subject)

    filtered_materials = query.order_by(Material.id.desc()).all()
    return render_template('materials.html', materials=filtered_materials, grade=grade, subject=subject)

@app.route('/materials/<grade>/<subject>')
def materials_by_subject(grade, subject):
    filtered_materials = Material.query.filter_by(grade=grade, subject=subject).order_by(Material.id.desc()).all()
    return render_template('materials.html', materials=filtered_materials, grade=grade, subject=subject)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if not current_user.is_admin:
        flash('You are not authorized to upload materials.', 'danger')
        return redirect(url_for('materials'))

    if request.method == 'POST':
        file = request.files.get('file')
        title = request.form.get('title')
        description = request.form.get('description')
        grade = request.form.get('grade')
        subject = request.form.get('subject')

        if not file or file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)

        if allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            new_material = Material(
                filename=filename,
                title=title,
                description=description,
                user_id=current_user.id,
                grade=grade,
                subject=subject
            )
            db.session.add(new_material)
            db.session.commit()
            flash('Material uploaded successfully!', 'success')
            return redirect(url_for('materials'))
        else:
            flash('File type not allowed', 'danger')
    return render_template('upload.html')

@app.route('/book', methods=['GET', 'POST'])
def book():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        date = request.form.get('date')

        new_booking = Booking(name=name, email=email, subject=subject, date=date)
        db.session.add(new_booking)
        db.session.commit()
        flash('Booking submitted successfully! You will be contacted soon.', 'success')
        return redirect(url_for('home'))
    return render_template('book.html')

@app.route('/grade10')
def grade10():
    return render_template('grade.html', grade='Grade 10')

@app.route('/grade11')
def grade11():
    return render_template('grade.html', grade='Grade 11')

@app.route('/grade12')
def grade12():
    return render_template('grade.html', grade='Grade 12')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already taken.', 'danger')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# ✅ NEW ROUTE: View single material + submit/view comments
@app.route('/material/<int:material_id>', methods=['GET', 'POST'])
def view_material(material_id):
    material = Material.query.get_or_404(material_id)
    comments = Comment.query.filter_by(material_id=material.id).order_by(Comment.timestamp.desc()).all()

    if request.method == 'POST' and current_user.is_authenticated:
        comment_text = request.form.get('comment')
        is_positive = request.form.get('is_positive') == 'true'  # 'true' or 'false' string

        if comment_text:
            new_comment = Comment(
                text=comment_text,
                user_id=current_user.id,
                material_id=material.id,
                is_positive=is_positive
            )
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment submitted!', 'success')
            return redirect(url_for('view_material', material_id=material.id))
        else:
            flash('Comment cannot be empty.', 'warning')

    return render_template('material_detail.html', material=material, comments=comments)

# ------------------------ MAIN ------------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
