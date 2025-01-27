from flask import Flask, render_template, request, redirect, url_for
from models import db, User
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'gokyswash'

db.init_app(app)
migrate = Migrate(app, db)

@app.before_request
def initialize_app():
    if not hasattr(app, "tables_created"):
        db.create_all()
        app.tables_created = True

@app.route('/')
def home():
    users = User.query.all()
    return render_template('user_info.html', users=users)

@app.route('/add', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        name = request.form['name']
        role = request.form['role']
        status = request.form.get('status', 'Unavailable')  
        new_user = User(name=name, role=role, status=status)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add_user.html')

@app.route('/update_status/<int:user_id>', methods=['POST'])
def update_status(user_id):
    user = User.query.get_or_404(user_id)
    new_status = request.form['status']
    user.status = new_status
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/delete_user/<int:user_id>', methods=['GET'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('home'))



if __name__ == '__main__':
    app.run(debug=True)
