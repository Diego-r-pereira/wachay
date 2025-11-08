from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Report, UserRole
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wachay.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()
    # Create a default admin user if one doesn't exist
    if not User.query.filter_by(username='admin').first():
        hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')
        admin_user = User(username='admin', password=hashed_password, role=UserRole.ADMIN)
        db.session.add(admin_user)
        db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/monitoring')
@login_required
def monitoring():
    if current_user.role != UserRole.GUARD:
        return redirect(url_for('index'))
    return render_template('monitoring.html')

@app.route('/admin')
@login_required
def admin():
    if current_user.role != UserRole.ADMIN:
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            if user.role == UserRole.ADMIN:
                return redirect(url_for('admin'))
            elif user.role == UserRole.GUARD:
                return redirect(url_for('monitoring'))
            else:
                return redirect(url_for('index'))
        return 'Invalid username or password'
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

from notifications import send_whatsapp_message, send_telegram_message

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        new_report = Report(
            ranger_name=request.form['ranger_name'],
            report_time=request.form['report_time'],
            report_date=request.form['report_date'],
            google_maps_link=request.form['google_maps_link'],
            image_path='static/images/placeholder.jpg', # Placeholder
            description=request.form['description']
        )
        db.session.add(new_report)
        db.session.commit()

        # Send notifications
        message = f"Nuevo reporte de incendio: {new_report.description} en {new_report.google_maps_link}"
        send_whatsapp_message(message)
        send_telegram_message(message)

        return redirect(url_for('index'))
    return render_template('report.html')

from fireSet import predict_image

@app.route('/predict', methods=['POST'])
def predict():
    image_path = request.json['image']
    # The image path is a URL, so we need to extract the path relative to the static folder
    image_path = image_path.replace(request.host_url + 'static/', 'static/')
    prediction = predict_image(image_path)
    fire = prediction < 0.5  # If the prediction is less than 0.5, it's a fire
    return {'fire': fire}

@app.context_processor
def inject_user_role():
    return dict(UserRole=UserRole)
