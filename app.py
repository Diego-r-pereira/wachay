from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from config import Config
from models import db, User, Report
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from messaging import send_whatsapp_message, send_telegram_message
import asyncio
from fireSet import predict_image
import os

app = Flask(__name__, static_folder='assets')
app.config.from_object(Config)

db.init_app(app)

# Create database tables if they don't exist and add a default admin user
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', name='Default', last_name='Admin', role='admin')
        admin_user.set_password('adminpass') # Default password for admin
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created: username='admin', password='adminpass'")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Logged in successfully!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'ranger':
                return redirect(url_for('ranger_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/create_user', methods=['POST'])
def create_user():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    username = request.form['username']
    password = request.form['password']
    name = request.form['name']
    last_name = request.form['last_name']
    telegram_id = request.form.get('telegram_id')
    whatsapp_number = request.form.get('whatsapp_number')
    role = request.form['role']

    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'danger')
        return redirect(url_for('admin_dashboard'))

    new_user = User(username=username, name=name, last_name=last_name,
                    telegram_id=telegram_id, whatsapp_number=whatsapp_number, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash(f'User {username} created successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    user_to_delete = User.query.get_or_404(user_id)
    # Prevent admin from deleting themselves
    if user_to_delete.id == session['user_id']:
        flash("You cannot delete your own account.", 'danger')
        return redirect(url_for('admin_dashboard'))

    db.session.delete(user_to_delete)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_user/<int:user_id>', methods=['GET'])
def edit_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    user_to_edit = User.query.get_or_404(user_id)
    return render_template('edit_user.html', user=user_to_edit)

@app.route('/update_user/<int:user_id>', methods=['POST'])
def update_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    user_to_update = User.query.get_or_404(user_id)

    user_to_update.username = request.form['username']
    if request.form['password']:
        user_to_update.set_password(request.form['password'])
    user_to_update.name = request.form['name']
    user_to_update.last_name = request.form['last_name']
    user_to_update.telegram_id = request.form.get('telegram_id')
    user_to_update.whatsapp_number = request.form.get('whatsapp_number')
    user_to_update.role = request.form['role']

    db.session.commit()
    flash('User updated successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/ranger_dashboard')
def ranger_dashboard():
    if 'user_id' not in session or session['role'] != 'ranger':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    ranger_name = user.name if user else "Ranger"
    return render_template('ranger_dashboard.html', ranger_name=ranger_name)

@app.route('/submit_report', methods=['POST'])
def submit_report():
    if 'user_id' not in session or session['role'] != 'ranger':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    ranger_name = request.form['ranger_name']
    report_time_str = request.form['report_time']
    report_date_str = request.form['report_date']
    google_maps_link = request.form['google_maps_link']
    description = request.form.get('description')

    try:
        report_time = datetime.strptime(report_time_str, '%H:%M').time()
        report_date = datetime.strptime(report_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash('Invalid time or date format.', 'danger')
        return redirect(url_for('ranger_dashboard'))

    new_report = Report(
        ranger_name=ranger_name,
        report_time=report_time,
        report_date=report_date,
        google_maps_link=google_maps_link,
        description=description
    )
    db.session.add(new_report)
    db.session.commit()

    # Send alerts
    alert_message = (
        f"ALERTA: Forest Fire Report!\n"
        f"Ranger: {ranger_name}\n"
        f"Time: {report_time_str}\n"
        f"Date: {report_date_str}\n"
        f"Location: {google_maps_link}\n"
        f"Description: {description if description else 'No description provided.'}"
    )

    # Get ranger's contact info for WhatsApp
    ranger_user = User.query.get(session['user_id'])
    whatsapp_sent = False
    if ranger_user and ranger_user.whatsapp_number:
        try:
            send_whatsapp_message(ranger_user.whatsapp_number, alert_message)
            whatsapp_sent = True
        except Exception as e:
            print(f"Error sending WhatsApp message: {e}")

    # Send Telegram message
    telegram_sent = False
    try:
        asyncio.run(send_telegram_message(alert_message))
        telegram_sent = True
    except Exception as e:
        print(f"Error sending Telegram message: {e}")

    if whatsapp_sent and telegram_sent:
        new_report.status = 'Sent'
    elif whatsapp_sent or telegram_sent:
        new_report.status = 'Partially Sent'
    else:
        new_report.status = 'Failed'

    db.session.commit()

    flash('Report submitted successfully and alerts sent!', 'success')
    return redirect(url_for('ranger_dashboard'))

@app.route('/reports')
def reports():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    all_reports = Report.query.all()
    return render_template('reports.html', reports=all_reports)

@app.route('/delete_report/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    report_to_delete = Report.query.get_or_404(report_id)
    db.session.delete(report_to_delete)
    db.session.commit()
    flash('Report deleted successfully!', 'success')
    return redirect(url_for('reports'))

@app.route('/edit_report/<int:report_id>', methods=['GET'])
def edit_report(report_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    report_to_edit = Report.query.get_or_404(report_id)
    return render_template('edit_report.html', report=report_to_edit)

@app.route('/update_report/<int:report_id>', methods=['POST'])
def update_report(report_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    report_to_update = Report.query.get_or_404(report_id)

    report_to_update.ranger_name = request.form['ranger_name']
    report_to_update.report_time = datetime.strptime(request.form['report_.time'], '%H:%M').time()
    report_to_update.report_date = datetime.strptime(request.form['report_date'], '%Y-%m-%d').date()
    report_to_update.google_maps_link = request.form['google_maps_link']
    report_to_update.description = request.form.get('description')
    report_to_update.status = request.form['status']

    db.session.commit()
    flash('Report updated successfully!', 'success')
    return redirect(url_for('reports'))


@app.route('/detect_fire', methods=['POST'])
def detect_fire():
    if 'user_id' not in session or session['role'] != 'ranger':
        return jsonify({'error': 'Unauthorized access'}), 403

    if 'image' not in request.files:
        return jsonify({'error': 'No image part'}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No selected image'}), 400

    if file:
        # Save the uploaded file temporarily
        upload_folder = os.path.join(app.root_path, 'uploads')
        os.makedirs(upload_folder, exist_ok=True)
        filepath = os.path.join(upload_folder, file.filename)
        file.save(filepath)

        # Predict using the fire detection model
        prediction_score = predict_image(filepath)
        os.remove(filepath)  # Clean up the temporary file

        if prediction_score is not None:
            if prediction_score > 0.5:  # Assuming 0.5 as threshold for fire detection
                result_text = f'Fire detected (Score: {prediction_score:.2f})'
            else:
                result_text = f'No fire detected (Score: {prediction_score:.2f})'
            return jsonify({'result': result_text})
        else:
            return jsonify({'error': 'Error processing image for detection.'}), 500
    
    return jsonify({'error': 'An unexpected error occurred.'}), 500

@app.route('/predict_carousel_image', methods=['POST'])
def predict_carousel_image():
    if 'user_id' not in session or session['role'] != 'ranger':
        return jsonify({'error': 'Unauthorized access'}), 403

    image_name = request.json.get('image_name')
    if not image_name:
        return jsonify({'error': 'No image name provided'}), 400

    image_path = os.path.join(app.static_folder, 'img', 'carousel', image_name)

    if not os.path.exists(image_path):
        return jsonify({'error': 'Image not found'}), 404

    prediction_score = predict_image(image_path)

    if prediction_score is not None:
        if prediction_score > 0.5:
            prediction_text = f'Fire Detected (Score: {prediction_score:.2f})'
        else:
            prediction_text = f'No Fire Detected (Score: {prediction_score:.2f})'
        return jsonify({'prediction': prediction_text})
    else:
        return jsonify({'error': 'Error processing image'}), 500

if __name__ == '__main__':
    app.run(debug=True)
