from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import db, User, Call, AuthUser, Role, Record, Bolo, Civilian
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cad_data.db' 
app.config['SQLALCHEMY_BINDS'] = {
    'auth': 'sqlite:///auth.db'
}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'gokyswash'

app.config['SESSION_TYPE'] = 'filesystem'  # Use filesystem-based session storage
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # Ensures cookies are signed for security



db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return AuthUser.query.get(int(user_id))

def seed_roles():
    default_roles = ["LEO", "FD", "Dispatch", "Civilian"]
    for role_name in default_roles:
        if not Role.query.filter_by(name=role_name).first():
            db.session.add(Role(name=role_name))
    db.session.commit()

@app.before_request
def initialize_app():
    with app.app_context():
        db.create_all()
        seed_roles()

@login_manager.user_loader
def load_user(user_id):
    return AuthUser.query.get(int(user_id))

PERMISSION_KEYS = {
    "ISP": "LEO",
    "RFD": "FD",
    "WCDOC": "Dispatch",
    "CIV": "Civilian"
}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home')) 

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = AuthUser.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session.clear()
            login_user(user)  # Log the user in
            session.pop('_flashes', None)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            session.pop('_flashes', None)
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        entered_keys = request.form['permission_keys'].replace(" ", "").split(",")

        existing_user = AuthUser.query.filter_by(username=username).first()
        if existing_user:
            session.pop('_flashes', None)
            flash("Username already taken. Please choose another.", "danger")
            return redirect(url_for("signup"))

        new_user = AuthUser(username=username)
        new_user.set_password(password)

        assigned_roles = set()
        for key in entered_keys:
            role_name = PERMISSION_KEYS.get(key)
            if role_name:
                new_user.add_role(role_name)
                assigned_roles.add(role_name)

        if not assigned_roles:
            session.pop('_flashes', None)
            flash("Invalid permission keys. Please try again.", "danger")
            return redirect(url_for("signup"))

        db.session.add(new_user)
        db.session.commit()

        session.pop('_flashes', None)
        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for("login"))

    roles = Role.query.all()
    return render_template("signup.html", roles=roles)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('_flashes', None)
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/account')
def account():
    return render_template('account.html')

@app.route('/')
def home():
    return render_template('communitymenu.html')

@app.route('/about')
def aboutus():
    return render_template('aboutus.html')

@app.route('/rms')
def rms():
    return render_template('recordsmanagement.html')

@app.route('/lookup', methods=['GET', 'POST'])
def lookup():
    records = None
    bolos = None
    name=None

    if request.method == 'POST':
        name = request.form['name']
        records = Record.query.filter(Record.name.ilike(f"%{name}%")).all()
        bolos = Bolo.query.filter(Bolo.name.ilike(f"%{name}%")).all()

    return render_template('recordslookup.html', records=records, bolos=bolos, name=name)

@app.route('/makearrest', methods=['GET', 'POST'])
def make_arrest():
    if request.method == 'POST':
        name = request.form['name']
        type = "Arrest"
        arresting_officer = request.form['arresting_officer']
        charges = request.form['charges']
        narrative = request.form['narrative']
        fine = request.form['fine']
        sentence = request.form['sentence']

        new_arrest = Record(
            name=name,
            type=type,
            arresting_officer = arresting_officer,
            charges = charges,
            narrative = narrative,
            fine = fine,
            sentence = sentence
        )

        db.session.add(new_arrest)
        db.session.commit()

        return redirect(url_for('dispatch'))
    
    return render_template('makearrest.html')

@app.route('/makepersonalarrest/<int:user_id>', methods=['GET', 'POST'])
def make_personal_arrest(username):

    if request.method == 'POST':
        name = username
        type = "Arrest"
        arresting_officer = request.form['arresting_officer']
        charges = request.form['charges']
        narrative = request.form['narrative']
        fine = request.form['fine']
        sentence = request.form['sentence']

        new_arrest = Record(
            name=name,  
            type=type,
            arresting_officer = arresting_officer,
            charges = charges,
            narrative = narrative,
            fine = fine,
            sentence = sentence
        )

        db.session.add(new_arrest)
        db.session.commit()

        return redirect(url_for('rms'))
    
    return render_template('makepersonalarrest.html', username=username)


@app.route('/makecitation', methods=['GET', 'POST'])
def make_citation():
    if request.method == 'POST':
        name = request.form['name']
        type = "Citation"
        arresting_officer = request.form['arresting_officer']
        charges = request.form['charges']
        narrative = request.form['narrative']
        fine = request.form['fine']
        sentence = "None"

        new_arrest = Record(
            name=name,
            type=type,
            arresting_officer = arresting_officer,
            charges = charges,
            narrative = narrative,
            fine = fine,
            sentence = sentence
        )

        db.session.add(new_arrest)
        db.session.commit()

        return redirect(url_for('dispatch'))
    
    return render_template('makecitation.html')

@app.route('/makebolo', methods=['GET', 'POST'])
def make_bolo():
    if request.method == 'POST':
        name = request.form['name']
        officer = request.form['officer']
        charges = request.form['charges']
        narrative = request.form['narrative']

        new_bolo = Bolo(
            name=name,
            officer=officer,
            charges=charges,
            narrative=narrative
        )

        db.session.add(new_bolo)
        db.session.commit()

        return redirect(url_for('rms'))
    
    return render_template('makebolo.html')

@app.route('/editrecord/<int:record_id>', methods=['GET', 'POST'])
def edit_record(record_id):
    record = Record.query.get_or_404(record_id)

    print(record.name)

    if request.method == "POST":
        if 'name' not in request.form:
            return redirect(url_for('edit_record', record_id=record.id))
        
        record.type = request.form['type']
        record.name = request.form['name']
        record.arresting_officer = request.form['arresting_officer']
        record.charges = request.form['charges']
        record.narrative = request.form['narrative']
        record.fine = request.form['fine']
        record.sentence = request.form['sentence']

        try:
            db.session.commit()
            return redirect(url_for('lookup'))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error: {str(e)}", "danger")
        

    
    return render_template('editrecord.html', record=record)

@app.route('/editbolo/<int:bolo_id>', methods=['GET', 'POST'])
def edit_bolo(bolo_id):
    bolo = Bolo.query.get_or_404(bolo_id)

    print(bolo.name)

    if request.method == "POST":
        if 'name' not in request.form:
            return redirect(url_for('edit_bolo', bolo_id=bolo.id))
        
        bolo.name = request.form['name']
        bolo.officer = request.form['officer']
        bolo.charges = request.form['charges']
        bolo.narrative = request.form['narrative']

        try:
            db.session.commit()
            return redirect(url_for('lookup'))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error: {str(e)}", "danger")
        

    
    return render_template('editbolo.html', bolo=bolo)


@app.route('/dispatch')
@login_required
def dispatch():
    if not current_user.has_role("Dispatch"):
        session.pop('_flashes', None)
        flash("Access denied.", "danger")
        return redirect(url_for("home"))
    
    users = User.query.all()
    calls = Call.query.all()
    return render_template('dispatch.html', users=users, calls=calls)

@app.route('/leo')
@login_required
def leo():
    if not current_user.has_role("LEO"):
        session.pop('_flashes', None)
        flash("Access denied.", "danger")
        return redirect(url_for('home'))
    
    return render_template('leo.html')

@app.route('/civ')
@login_required
def civ():
    if not current_user.has_role("Civilian"):
        session.pop('_flashes', None)
        flash("Access denied.", "danger")
        return redirect(url_for('home'))
        
    
    civilians = Civilian.query.filter_by(auth_id=current_user.id).all()

    for civilian in civilians:
        civilian.date_of_birth = datetime.strptime(civilian.date_of_birth, '%Y-%m-%d').strftime('%m/%d/%Y')
    return render_template('civilian.html', civilians=civilians)

@app.route('/fd')
@login_required
def fd():
    if not current_user.has_role("FD"):
        session.pop('_flashes', None)
        flash("Access denied.", "danger")
        return redirect(url_for('home'))
    
    return render_template('firedept.html')

@app.route('/add', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        name = request.form['name']
        role = request.form['role']
        callsign = request.form['callsign']
        status = request.form.get('status', 'Unavailable')
        department = request.form.get('department', 'N/A')
        subdivision = request.form.get('subdivision', 'N/A')
        rank = request.form.get('rank', 'N/A')
        aop = request.form.get('aop', 'N/A')
        new_user = User(name=name, role=role, status=status, callsign=callsign, department=department, subdivision=subdivision, rank=rank, aop=aop)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('dispatch'))
    return render_template('add_user.html')

@app.route('/createcall', methods=['GET', 'POST'])
def create_call():
    if request.method == 'POST':
        call_origin = request.form['call_origin']
        call_status = request.form['call_status']
        address = request.form['address']
        call_title = request.form['call_title']
        code = request.form['code']
        call_description = request.form.get('call_description')  # Optional field

        new_call = Call(
            call_origin=call_origin,
            call_status=call_status,
            address=address,
            call_title=call_title,
            code=code,
            call_description=call_description,
            attached_units="None"
        )

        db.session.add(new_call)
        db.session.commit()

        return redirect(url_for('dispatch'))

    return render_template('createcall.html')

@app.route('/editcall/<int:call_id>', methods=['GET', 'POST'])
def edit_call(call_id):
    call = Call.query.get_or_404(call_id)
    users = User.query.all()

    if request.method == 'POST':
        call.call_status = request.form['call_status']
        call.address = request.form['address']
        call.call_title = request.form['call_title']
        call.code = request.form['code']
        call.call_description = request.form['call_description']
        
        selected_units = request.form.getlist('attached_units')
        call.attached_units = ", ".join(selected_units)

        db.session.commit()
        return redirect(url_for('dispatch'))

    return render_template('editcall.html', call=call, users=users)



@app.route('/viewcall/<int:call_id>', methods=['GET', 'POST'])
def view_call(call_id):
    call = Call.query.get_or_404(call_id)

    if request.method == 'POST':
        return redirect(url_for('dispatch'))

    return render_template('viewcall.html', call=call)

@app.route('/update_status/<int:user_id>', methods=['POST'])
def update_status(user_id):
    user = User.query.get_or_404(user_id)
    new_status = request.form['status']
    user.status = new_status
    db.session.commit()
    return redirect(url_for('dispatch'))

@app.route('/delete_call/<int:call_id>', methods=['POST'])
def delete_call(call_id):
    call = Call.query.get_or_404(call_id)
    db.session.delete(call)
    db.session.commit()
    return redirect(url_for('dispatch'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('dispatch'))

@app.route('/void_bolo/<int:bolo_id>', methods=['POST'])
def void_bolo(bolo_id):
    bolo = Bolo.query.get_or_404(bolo_id)
    db.session.delete(bolo)
    db.session.commit()
    return redirect(url_for('lookup'))

@app.route('/void_record/<int:record_id>', methods=['POST'])
def void_record(record_id):
    record = Record.query.get_or_404(record_id)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for('lookup'))

@app.route("/delete_account/<int:account_id>", methods=["GET", "POST"])
@login_required
def delete_account(account_id):
    if request.method == "GET":
        session.pop('_flashes', None)
        flash("Account deletion requires a POST request.", "danger")
        return redirect(url_for('account'))

    user = AuthUser.query.get_or_404(account_id)
    print(user.username)
    db.session.delete(user)
    db.session.commit()
    session.pop('_flashes', None)
    flash("Your account has been deleted.", "success")
    return redirect(url_for('logout'))

@app.route('/createcivilian', methods=['GET', 'POST'])
@login_required
def create_civilian():
    if request.method == 'POST':
        print(request.form)  # Debugging step

        if request.method == "POST":
            if 'first_name' not in request.form:
                return redirect(url_for('create_civilian'))

        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        middle_initial = request.form["middle_initial"]
        date_of_birth = request.form["date_of_birth"]
        age = request.form["age"]
        sex = request.form["sex"]
        residence = request.form["residence"]
        zip_code = request.form["zip_code"]
        occupation = request.form["occupation"]
        height = request.form["height"]
        weight = request.form["weight"]
        skin_tone = request.form["skin_tone"]
        hair_color = request.form["hair_color"]
        eye_color = request.form["eye_color"]

        new_civilian = Civilian(
            auth_id=current_user.id,
            first_name=first_name,
            last_name=last_name,
            middle_initial=middle_initial,
            date_of_birth=date_of_birth,
            age=age,
            sex=sex,
            residence=residence,
            zip_code=zip_code,
            occupation=occupation,
            height=height,
            weight=weight,
            skin_tone=skin_tone,
            hair_color=hair_color,
            eye_color=eye_color)
        
        try: 
            db.session.add(new_civilian)
            db.session.commit()
            return redirect(url_for('civ'))
        except Exception as e:
            db.session.rollback()
            return render_template('createcivilian.html')
    
    return render_template('createcivilian.html')

@app.route('/viewcivilian/<int:civilian_id>', methods=['GET', 'POST'])
def view_civilian(civilian_id):
    civilian = Civilian.query.get_or_404(civilian_id)

    if request.method == 'POST':
        return redirect(url_for('civ'))
    
    return render_template('viewcivilian.html', civilian=civilian)

if __name__ == '__main__':
    app.run(debug=True)
