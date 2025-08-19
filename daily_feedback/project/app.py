from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from functools import wraps
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///student_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'ppt', 'pptx', 'xlsx', 'zip', 'mp4', 'avi'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.email}>'

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assigned_to_all = db.Column(db.Boolean, default=False)
    due_date = db.Column(db.String(50))
    resource_file = db.Column(db.String(500))  # File uploaded by admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    assigned_by_user = db.relationship('User', foreign_keys=[assigned_by])
    assigned_to_user = db.relationship('User', foreign_keys=[assigned_to])

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submitted_file = db.Column(db.String(500))
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    activity = db.relationship('Activity', backref='submissions')
    student = db.relationship('User', backref='submissions')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default='info')
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='notifications')

# Create database tables and admin user
with app.app_context():
    db.create_all()
    
    # Create admin user if it doesn't exist
    admin = User.query.filter_by(email='ttpskillcbe@gmail.com').first()
    if not admin:
        admin_user = User(
            name='ttp',
            email='ttpskillcbe@gmail.com',
            password_hash=generate_password_hash('Admin@123'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created: ttpskillcbe@gmail.com / Admin@123")

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required!', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['name'] = user.name
            session['role'] = user.role
            session['email'] = user.email
            
            flash(f'Welcome {user.name}!', 'success')
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid email or password!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not all([name, email, password, confirm_password]):
            flash('All fields are required!', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'error')
            return render_template('register.html')
        
        # Create new user
        try:
            hashed_password = generate_password_hash(password)
            new_user = User(
                name=name,
                email=email,
                password_hash=hashed_password,
                role='student'
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    # Get statistics
    total_students = User.query.filter_by(role='student').count()
    total_activities = Activity.query.count()
    total_submissions = Submission.query.count()
    
    # Get recent activities
    activities = Activity.query.order_by(Activity.created_at.desc()).limit(10).all()
    
    # Get all students
    students = User.query.filter_by(role='student').order_by(User.name).all()
    
    # Get recent submissions
    submissions = db.session.query(Submission, Activity, User)\
                    .join(Activity, Submission.activity_id == Activity.id)\
                    .join(User, Submission.student_id == User.id)\
                    .order_by(Submission.submitted_at.desc()).limit(10).all()
    
    stats = {
        'total_students': total_students,
        'total_activities': total_activities,
        'total_submissions': total_submissions
    }
    
    return render_template('admin_dashboard.html', 
                         stats=stats, 
                         activities=activities, 
                         students=students,
                         recent_submissions=submissions)

@app.route('/student')
@login_required
def student_dashboard():
    if session['role'] != 'student':
        return redirect(url_for('admin_dashboard'))
    
    # Get activities assigned to this student or all students
    activities = Activity.query.filter(
        (Activity.assigned_to == session['user_id']) | 
        (Activity.assigned_to_all == True)
    ).order_by(Activity.created_at.desc()).all()
    
    # Get submissions by this student
    submissions = Submission.query.filter_by(student_id=session['user_id']).all()
    submission_dict = {sub.activity_id: sub for sub in submissions}
    
    return render_template('student_dashboard.html', 
                         activities=activities,
                         submissions=submission_dict)

@app.route('/assign_activity', methods=['POST'])
@admin_required
def assign_activity():
    try:
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        assigned_to = request.form.get('assigned_to', '')
        due_date = request.form.get('due_date', '')
        
        if not title:
            flash('Activity title is required!', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Handle file upload
        resource_file = None
        if 'resource_file' in request.files:
            file = request.files['resource_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add timestamp to avoid conflicts
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = timestamp + filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                resource_file = filename
        
        # Create activity
        activity = Activity(
            title=title,
            description=description,
            assigned_by=session['user_id'],
            resource_file=resource_file,
            due_date=due_date if due_date else None
        )
        
        if assigned_to == 'all':
            activity.assigned_to_all = True
            # Notify all students
            students = User.query.filter_by(role='student').all()
            for student in students:
                notification = Notification(
                    user_id=student.id,
                    message=f'New activity assigned: {title}',
                    type='activity'
                )
                db.session.add(notification)
        else:
            activity.assigned_to = int(assigned_to)
            # Notify specific student
            notification = Notification(
                user_id=int(assigned_to),
                message=f'New activity assigned: {title}',
                type='activity'
            )
            db.session.add(notification)
        
        db.session.add(activity)
        db.session.commit()
        
        flash('Activity assigned successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error assigning activity: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/submit_activity/<int:activity_id>', methods=['POST'])
@login_required
def submit_activity(activity_id):
    if session['role'] != 'student':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        activity = Activity.query.get_or_404(activity_id)
        
        # Check if student has permission to submit
        if not (activity.assigned_to == session['user_id'] or activity.assigned_to_all):
            return jsonify({'error': 'Access denied'}), 403
        
        # Check if already submitted
        existing_submission = Submission.query.filter_by(
            activity_id=activity_id,
            student_id=session['user_id']
        ).first()
        
        if existing_submission:
            return jsonify({'error': 'Activity already submitted'}), 400
        
        # Handle file upload
        submitted_file = None
        if 'submission_file' in request.files:
            file = request.files['submission_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add student name and timestamp to filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                student_name = session['name'].replace(' ', '_')
                filename = f"{student_name}_{timestamp}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                submitted_file = filename
        
        # Create submission
        submission = Submission(
            activity_id=activity_id,
            student_id=session['user_id'],
            submitted_file=submitted_file
        )
        
        db.session.add(submission)
        
        # Notify admin
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            notification = Notification(
                user_id=admin.id,
                message=f'{session["name"]} submitted activity: {activity.title}',
                type='submission'
            )
            db.session.add(notification)
        
        db.session.commit()
        
        flash('Activity submitted successfully!', 'success')
        return redirect(url_for('student_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error submitting activity: {str(e)}', 'error')
        return redirect(url_for('student_dashboard'))

@app.route('/view_submissions')
@admin_required
def view_submissions():
    # Get all submissions with related data
    submissions = db.session.query(Submission, Activity, User)\
                    .join(Activity, Submission.activity_id == Activity.id)\
                    .join(User, Submission.student_id == User.id)\
                    .order_by(Submission.submitted_at.desc()).all()
    
    return render_template('view_submissions.html', submissions=submissions)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if not os.path.exists(file_path):
            flash('File not found!', 'error')
            return redirect(request.referrer or url_for('index'))
        
        # Admin can download any file
        if session['role'] == 'admin':
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
        
        # Students can only download files they have access to
        if session['role'] == 'student':
            # Check if it's an activity resource file they have access to
            activity = Activity.query.filter(
                (Activity.resource_file == filename) &
                ((Activity.assigned_to == session['user_id']) | (Activity.assigned_to_all == True))
            ).first()
            
            # Check if it's their own submission
            submission = Submission.query.filter_by(
                submitted_file=filename,
                student_id=session['user_id']
            ).first()
            
            if activity or submission:
                return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
            else:
                flash('Access denied!', 'error')
                return redirect(url_for('student_dashboard'))
        
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
        
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(request.referrer or url_for('index'))

@app.route('/notifications')
@login_required
def get_notifications():
    notifications = Notification.query.filter_by(
        user_id=session['user_id'],
        read=False
    ).order_by(Notification.created_at.desc()).limit(10).all()
    
    return jsonify([{
        'id': n.id,
        'message': n.message,
        'type': n.type,
        'created_at': n.created_at.strftime('%Y-%m-%d %H:%M')
    } for n in notifications])

@app.route('/mark_notifications_read', methods=['POST'])
@login_required
def mark_notifications_read():
    try:
        Notification.query.filter_by(
            user_id=session['user_id'],
            read=False
        ).update({'read': True})
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)})

# Template filters
@app.template_filter('datetime')
def datetime_filter(value):
    if value is None:
        return 'Unknown'
    if isinstance(value, str):
        return value
    return value.strftime('%Y-%m-%d %H:%M')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)