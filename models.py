from flask_sqlalchemy import SQLAlchemy
import random
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# Define association table before AuthUser and Role classes
auth_user_roles = db.Table(
    'auth_user_roles',
    db.Column('auth_user_id', db.Integer, db.ForeignKey('auth_user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    bind_key='auth'  # Ensure the association table uses the 'auth' database
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(100), nullable=False, default='Unavailable')
    callsign = db.Column(db.String(5), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    subdivision = db.Column(db.String(50), nullable=False)
    rank = db.Column(db.String(50), nullable=False)
    aop = db.Column(db.String(50), nullable=False)

class Call(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    call_origin = db.Column(db.String(100), nullable=False)
    call_status = db.Column(db.String(50), nullable=False, default="Pending")
    address = db.Column(db.String(200), nullable=False)
    call_title = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10), nullable=False)
    call_description = db.Column(db.Text, nullable=False)
    attached_units = db.Column(db.Text, nullable=False, default="None")

class Role(db.Model):
    __bind_key__ = 'auth'  # Explicitly bind Role model to the 'auth' database
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f"<Role(id={self.id}, name={self.name})>"

class AuthUser(db.Model):
    __tablename__ = "auth_user"
    __bind_key__ = "auth"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    roles = db.relationship('Role', secondary=auth_user_roles, backref=db.backref('users', lazy='dynamic'))

    @property
    def is_active(self):
        return True  # Returning True by default

    @property
    def is_authenticated(self):
        # This is used by Flask-Login to check if the user is logged in
        return True  # Set this to True since you're not implementing your own custom check

    @property
    def is_anonymous(self):
        return False  # Indicates that the user is not anonymous

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def add_role(self, role_name):
        """Assign a role to the user."""
        role = Role.query.filter_by(name=role_name).first()
        if role and role not in self.roles:
            self.roles.append(role)

    def remove_role(self, role_name):
        """Remove a role from the user."""
        role = Role.query.filter_by(name=role_name).first()
        if role and role in self.roles:
            self.roles.remove(role)

    def has_role(self, role_name):
        """Check if user has a specific role."""
        return any(role.name == role_name for role in self.roles)
    
    def get_id(self):
        return str(self.id)  # Ensure that it returns a string
    
# RMS

# Records
class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    arresting_officer = db.Column(db.String(100), nullable=False)
    charges = db.Column(db.String, nullable=False)
    narrative = db.Column(db.String, nullable=False)
    fine = db.Column(db.String, nullable=False)
    sentence = db.Column(db.String, nullable=False)

class Bolo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    officer = db.Column(db.String(100), nullable=False)
    charges = db.Column(db.String, nullable=False)
    narrative = db.Column(db.String, nullable=False)\

class Civilian(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    auth_id = db.Column(db.Integer, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    middle_initial = db.Column(db.String(5), nullable=False)
    date_of_birth = db.Column(db.String(100), nullable=False)
    age = db.Column(db.String(3), nullable=False)
    sex = db.Column(db.String(100), nullable=False)
    residence = db.Column(db.String(100), nullable=False)
    zip_code = db.Column(db.String(10), nullable=False)
    occupation = db.Column(db.String(100), nullable=False)
    height = db.Column(db.String(100), nullable=False)
    weight = db.Column(db.String(100), nullable=False)
    skin_tone = db.Column(db.String(100), nullable=False)
    hair_color = db.Column(db.String(100), nullable=False)
    eye_color = db.Column(db.String(100), nullable=False)

