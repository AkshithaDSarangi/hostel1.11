# app.py
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hostel_management_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hostel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'student'
    
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    is_super_admin = db.Column(db.Boolean, default=False)  # Flag for super admin privileges
    
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    course = db.Column(db.String(50), nullable=False)
    district = db.Column(db.String(75), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    annual_income = db.Column(db.Integer, nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=True)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(10), unique=True, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    occupied = db.Column(db.Integer, default=0)
    hostel_block = db.Column(db.String(10), nullable=False)
    students = db.relationship('Student', backref='room')

class RoomApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    preferred_block = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    application_date = db.Column(db.DateTime, default=datetime.utcnow)
    student = db.relationship('Student', backref='applications')

class Fee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)
    semester = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='unpaid')  # unpaid, paid
    transaction_id = db.Column(db.String(50), nullable=True)
    student = db.relationship('Student', backref='fees')

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False)  # present, absent
    student = db.relationship('Student', backref='attendance')


class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    student = db.relationship('Student', backref=db.backref('complaints', lazy=True))

# Initialize the database
with app.app_context():
    db.create_all()


# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/admin/room/add', methods=['GET', 'POST'])
def add_rooms():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        room_number = request.form.get('room_number')
        capacity = request.form.get('capacity')
        hostel_block = request.form.get('hostel_block')
        
        new_room = Room(
            room_number=room_number,
            capacity=capacity,
            hostel_block=hostel_block
        )
        
        db.session.add(new_room)
        db.session.commit()
        flash('Room added successfully', 'success')
        return redirect(url_for('admin_rooms'))
    
    return render_template('admin/add_room.html')

@app.route('/admin/room/<int:room_id>', methods=['GET'])
def view_rooms(room_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    room = Room.query.get_or_404(room_id)
    return render_template('admin/view.html', room=room)


@app.route('/admin/room/<int:room_id>', methods=['GET'])
def view_room(room_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    room = Room.query.get_or_404(room_id)
    return render_template('admin/room_details.html', room=room)

@app.route('/admin/room/<int:room_id>/edit', methods=['GET', 'POST'])
def edit_room(room_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    room = Room.query.get_or_404(room_id)
    
    if request.method == 'POST':
        room.room_number = request.form.get('room_number')
        room.capacity = request.form.get('capacity')
        room.hostel_block = request.form.get('hostel_block')
        
        db.session.commit()
        flash('Room updated successfully', 'success')
        return redirect(url_for('view_room', room_id=room.id))
    
    return render_template('admin/edit.html', room=room)

@app.route('/admin/room/<int:room_id>/delete', methods=['POST'])
def delete_room(room_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    room = Room.query.get_or_404(room_id)
    db.session.delete(room)
    db.session.commit()
    flash('Room deleted successfully', 'success')
    return redirect(url_for('admin_rooms'))

# Route for students to submit complaints
@app.route('/student/complaint', methods=['GET', 'POST'])
def student_complaint():
    if 'user_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    student = Student.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        complaint_text = request.form.get('complaint')
        
        new_complaint = Complaint(student_id=student.id, text=complaint_text, status='pending')
        db.session.add(new_complaint)
        db.session.commit()
        
        flash('Complaint submitted successfully', 'success')
        return redirect(url_for('student_dashboard'))
    
    return render_template('student/complaint.html')

# Route for admin to view complaints
@app.route('/admin/complaints')
def admin_complaints():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    complaints = Complaint.query.all()
    return render_template('admin/complaints.html', complaints=complaints)

# Route for admin to resolve complaints
@app.route('/admin/complaint/<int:complaint_id>/resolve')
def resolve_complaint(complaint_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    complaint = Complaint.query.get_or_404(complaint_id)
    complaint.status = 'resolved'
    db.session.commit()
    flash('Complaint resolved successfully', 'success')
    
    return redirect(url_for('admin_complaints'))



@app.route('/student/signup', methods=['GET', 'POST'])
def student_signup():
    if request.method == 'POST':
        # Form validation
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        course = request.form.get('course')
        district = request.form.get('district')
        year = request.form.get('year')
        annual_income = request.form.get('annual_income')
        
        # Comprehensive validation
        if not all([username, password, name, email, phone, address, course, district, year , annual_income]):
            flash('All fields are required', 'danger')
            return redirect(url_for('student_signup'))
        
        # Username validation
        if len(username) < 4:
            flash('Username must be at least 4 characters long', 'danger')
            return redirect(url_for('student_signup'))
        
        # Password validation
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return redirect(url_for('student_signup'))
        
        # Email validation (basic)
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email format', 'danger')
            return redirect(url_for('student_signup'))
        
        # Phone validation (basic)
        if not re.match(r'^\d{10}$', phone):
            flash('Phone number must be 10 digits', 'danger')
            return redirect(url_for('student_signup'))
        
        # Check if username or email already exists
        existing_user = User.query.filter_by(username=username).first()
        existing_email = Student.query.filter_by(email=email).first()
        
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('student_signup'))
        
        if existing_email:
            flash('Email already registered. Please use a different email.', 'danger')
            return redirect(url_for('student_signup'))
        
        # Create new user
        try:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password, role='student')
            db.session.add(new_user)
            db.session.flush()  # Flush to get the new user's ID
            
            # Create new student
            new_student = Student(
                user_id=new_user.id,
                name=name,
                email=email,
                phone=phone,
                address=address,
                course=course,
                district=district,
                year=int(year),
                annual_income=int(annual_income)
            )
            
            db.session.add(new_student)
            db.session.commit()
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            app.logger.error(f"Registration error: {str(e)}")
    
    return render_template('student_signup.html')

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        # Form validation
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Comprehensive validation
        if not all([username, password, confirm_password]):
            flash('All fields are required', 'danger')
            return redirect(url_for('admin_signup'))
        
        # Username validation
        if len(username) < 4:
            flash('Username must be at least 4 characters long', 'danger')
            return redirect(url_for('admin_signup'))
        
        # Password validation
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return redirect(url_for('admin_signup'))
        
        # Password match validation
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('admin_signup'))
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('admin_signup'))
        
        # Create new admin user
        try:
            hashed_password = generate_password_hash(password)
            new_admin = User(username=username, password=hashed_password, role='admin')
            
            db.session.add(new_admin)
            db.session.commit()
            
            flash('Admin registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            app.logger.error(f"Admin Registration error: {str(e)}")
    
    return render_template('admin_signup.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('home'))

# Admin Routes
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    applications = RoomApplication.query.filter_by(status='pending').count()
    students = Student.query.count()
    rooms = Room.query.count()
    fees_pending = Fee.query.filter_by(status='unpaid').count()
    
    return render_template('admin/dashboard.html', 
                           applications=applications,
                           students=students,
                           rooms=rooms,
                           fees_pending=fees_pending)

@app.route('/admin/rooms')
def admin_rooms():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    rooms = Room.query.all()
    return render_template('admin/rooms.html', rooms=rooms)

@app.route('/admin/room/add', methods=['GET', 'POST'])
def add_room():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        room_number = request.form.get('room_number')
        capacity = request.form.get('capacity')
        hostel_block = request.form.get('hostel_block')
        
        new_room = Room(
            room_number=room_number,
            capacity=capacity,
            hostel_block=hostel_block
        )
        
        db.session.add(new_room)
        db.session.commit()
        flash('Room added successfully', 'success')
        return redirect(url_for('admin_rooms'))
    
    return render_template('admin/add_room.html')

@app.route('/admin/applications')
def admin_applications():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    applications = RoomApplication.query.filter_by(status='pending').all()
    return render_template('admin/applications.html', applications=applications)

@app.route('/admin/application/<int:id>/<action>')
def process_application(id, action):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    application = RoomApplication.query.get_or_404(id)
    
    if action == 'approve':
        # Find an available room in the preferred block
        room = Room.query.filter_by(hostel_block=application.preferred_block).filter(Room.occupied < Room.capacity).first()
        
        if room:
            student = Student.query.get(application.student_id)
            student.room_id = room.id
            room.occupied += 1
            application.status = 'approved'
            db.session.commit()
            flash('Application approved and room allocated', 'success')
        else:
            flash('No rooms available in the preferred block', 'danger')
    
    elif action == 'reject':
        application.status = 'rejected'
        db.session.commit()
        flash('Application rejected', 'success')
    
    return redirect(url_for('admin_applications'))

@app.route('/admin/students')
def admin_students():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    students = Student.query.all()
    return render_template('admin/students.html', students=students)

@app.route('/admin/fees')
def admin_fees():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    fees = Fee.query.all()
    return render_template('admin/fees.html', fees=fees)

@app.route('/admin/attendance')
def admin_attendance():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    students = Student.query.all()
    return render_template('admin/attendance.html', students=students)

@app.route('/admin/attendances', methods=['GET'])
def admin_attendances():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    students = Student.query.all()  # Fetch all students
    return render_template('admin/attendances.html', students=students)

@app.route('/admin/mark_attendance', methods=['POST'])
def mark_attendance():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
    
    for key, value in request.form.items():
        if key.startswith('student_'):
            student_id = int(key.split('_')[1])
            
            # Check if attendance already exists for this student on this date
            existing = Attendance.query.filter_by(student_id=student_id, date=date).first()
            
            if existing:
                existing.status = value
            else:
                new_attendance = Attendance(
                    student_id=student_id,
                    date=date,
                    status=value
                )
                db.session.add(new_attendance)
    
    db.session.commit()
    flash('Attendance marked successfully', 'success')
    return redirect(url_for('admin_attendance'))

# Student Routes
@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    student = Student.query.filter_by(user_id=user_id).first()
    
    # Get the application status
    application = RoomApplication.query.filter_by(student_id=student.id).order_by(RoomApplication.application_date.desc()).first()
    
    # Get fee status
    fees = Fee.query.filter_by(student_id=student.id).all()
    
    # Get attendance
    attendance = Attendance.query.filter_by(student_id=student.id).all()
    present_count = sum(1 for a in attendance if a.status == 'present')
    total_count = len(attendance)
    attendance_percentage = (present_count / total_count * 100) if total_count > 0 else 0
    
    return render_template('student/dashboard.html', 
                           student=student,
                           application=application,
                           fees=fees,
                           attendance_percentage=attendance_percentage)

@app.route('/student/apply', methods=['GET', 'POST'])
def student_apply():
    if 'user_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    student = Student.query.filter_by(user_id=user_id).first()
    
    # Check if student already has a room
    if student.room_id:
        flash('You already have a room allocated', 'info')
        return redirect(url_for('student_dashboard'))
    
    # Check if student already has a pending application
    pending = RoomApplication.query.filter_by(student_id=student.id, status='pending').first()
    if pending:
        flash('You already have a pending application', 'info')
        return redirect(url_for('student_dashboard'))
    
    if request.method == 'POST':
        preferred_block = request.form.get('preferred_block')
        
        new_application = RoomApplication(
            student_id=student.id,
            preferred_block=preferred_block
        )
        
        db.session.add(new_application)
        db.session.commit()
        flash('Application submitted successfully', 'success')
        return redirect(url_for('student_dashboard'))
    
    return render_template('student/apply.html')

@app.route('/student/fees')
def student_fees():
    if 'user_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    student = Student.query.filter_by(user_id=user_id).first()
    
    fees = Fee.query.filter_by(student_id=student.id).all()
    return render_template('student/fees.html', fees=fees)

@app.route('/student/pay_fee/<int:fee_id>', methods=['GET', 'POST'])
def pay_fee(fee_id):
    if 'user_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    fee = Fee.query.get_or_404(fee_id)
    
    user_id = session['user_id']
    student = Student.query.filter_by(user_id=user_id).first()
    
    # Check if the fee belongs to the logged-in student
    if fee.student_id != student.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('student_dashboard'))
    
    if request.method == 'POST':
        transaction_id = request.form.get('transaction_id')
        
        fee.status = 'paid'
        fee.payment_date = datetime.utcnow()
        fee.transaction_id = transaction_id
        
        db.session.commit()
        flash('Fee payment successful', 'success')
        return redirect(url_for('student_fees'))
    
    return render_template('student/pay_fee.html', fee=fee)

@app.route('/student/attendance')
def student_attendance():
    if 'user_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    student = Student.query.filter_by(user_id=user_id).first()
    
    attendance = Attendance.query.filter_by(student_id=student.id).order_by(Attendance.date.desc()).all()
    
    present_count = sum(1 for a in attendance if a.status == 'present')
    total_count = len(attendance)
    percentage = (present_count / total_count * 100) if total_count > 0 else 0
    
    return render_template('student/attendance.html', 
                           attendance=attendance, 
                           percentage=percentage)

# Initialize the database
def init_db():
    with app.app_context():
        db.create_all()
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_user = User(
                username='admin',
                password=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)