from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
import os
import secrets
from datetime import timedelta
from mongo_routes import mongo_routes

app = Flask(__name__)

app.register_blueprint(mongo_routes)

app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://flask_user:password@localhost/flask_project'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300))
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    if not username or not email or not password:
        return jsonify(message="All fields are required"), 400
    if User.query.filter_by(email=email).first():
        return jsonify(message="Email already exists"), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="User registered successfully"), 201

@app.route('/update_user', methods=['POST'])
@login_required
def update_user():
    user_id = session['_user_id']
    user = User.query.get_or_404(user_id)
    username = request.form.get('username', user.username)
    email = request.form.get('email', user.email)
    if not username or not email:
        return jsonify(message="Username and email cannot be empty"), 400
    user.username = username
    user.email = email
    db.session.commit()
    return jsonify(message="User information updated successfully"), 200

@app.route('/delete_user', methods=['DELETE'])
@login_required
def delete_user():
    user_id = session['_user_id']
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify(message="User account deleted successfully"), 200

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return jsonify(message="Username and password are required"), 400
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        session['username'] = user.username
        session['_user_id'] = user.id
        session.permanent = True
        return jsonify(message="Login successful"), 200
    return jsonify(message="Invalid credentials"), 401

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['_user_id']
    items = InventoryItem.query.filter_by(user_id=user_id).all()
    items_list = [{
        "id": item.id,
        "name": item.name,
        "description": item.description,
        "quantity": item.quantity,
        "price": item.price
    } for item in items]
    return jsonify(message=f"Welcome {session['username']} to your dashboard", items=items_list), 200

@app.route('/inventory', methods=['POST'])
@login_required
def create_item():
    name = request.form.get('name')
    description = request.form.get('description')
    quantity = request.form.get('quantity')
    price = request.form.get('price')
    if not name or not quantity or not price:
        return jsonify(message="Name, quantity, and price are required"), 400
    try:
        quantity = int(quantity)
        price = float(price)
    except ValueError:
        return jsonify(message="Quantity must be an integer and price must be a float"), 400
    new_item = InventoryItem(
        name=name,
        description=description,
        quantity=quantity,
        price=price,
        user_id=session['_user_id']
    )
    db.session.add(new_item)
    db.session.commit()
    return jsonify(message="Inventory item created successfully"), 201

@app.route('/update_item/<int:item_id>', methods=['POST'])
@login_required
def update_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if item.user_id != int(session['_user_id']):
        return jsonify(message="Unauthorized access"), 403
    name = request.form.get('name')
    quantity = request.form.get('quantity')
    price = request.form.get('price')
    if not name or not quantity or not price:
        return jsonify(message="Name, quantity, and price are required"), 400
    try:
        quantity = int(quantity)
        price = float(price)
    except ValueError:
        return jsonify(message="Quantity must be an integer and price must be a float"), 400
    item.name = name
    item.quantity = quantity
    item.price = price
    db.session.commit()
    return jsonify(message="Inventory item updated successfully"), 200

@app.route('/delete_item/<int:item_id>', methods=['DELETE'])
@login_required
def delete_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if item.user_id != int(session['_user_id']):
        return jsonify(message="Unauthorized access"), 403
    db.session.delete(item)
    db.session.commit()
    return jsonify(message="Inventory item deleted"), 200

if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
            print("Successfully connected to MySQL and initialized the database!")
        except Exception as e:
            print(f"Failed to connect to MySQL: {e}")
    app.run(debug=True)
