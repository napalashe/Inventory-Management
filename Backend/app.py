from flask import Flask, request, jsonify, session, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
import os
import secrets
from datetime import timedelta

app = Flask(__name__)

app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
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
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="User registered successfully"), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        login_user(user)
        session['username'] = user.username
        session['_user_id'] = user.id
        session.permanent = True
        return jsonify(message="Login successful"), 200
    return jsonify(message="Invalid credentials"), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    session.pop('_user_id', None)
    return jsonify(message="Logout successful"), 200

@app.route('/dashboard')
@login_required
def dashboard():
    return jsonify(message=f"Welcome {session['username']} to your dashboard!")

@app.route('/inventory', methods=['POST'])
@login_required
def create_item():
    data = request.get_json()
    new_item = InventoryItem(
        name=data['name'],
        description=data['description'],
        quantity=data['quantity'],
        price=data['price'],
        user_id=session['_user_id']
    )
    db.session.add(new_item)
    db.session.commit()
    return jsonify(message="Inventory item created successfully"), 201

@app.route('/inventory', methods=['GET'])
@login_required
def get_items():
    user_id = session['_user_id']
    items = InventoryItem.query.filter_by(user_id=user_id).all()
    return jsonify(items=[{
        'id': item.id,
        'name': item.name,
        'description': item.description,
        'quantity': item.quantity,
        'price': item.price
    } for item in items]), 200

@app.route('/inventory/<int:item_id>', methods=['GET'])
@login_required
def get_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if item.user_id != int(session['_user_id']):
        return jsonify(message="Unauthorized access"), 403
    return jsonify(
        id=item.id,
        name=item.name,
        description=item.description,
        quantity=item.quantity,
        price=item.price
    ), 200

@app.route('/inventory/<int:item_id>', methods=['PUT'])
@login_required
def update_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if item.user_id != int(session['_user_id']):
        return jsonify(message="Unauthorized access"), 403
    data = request.get_json()
    item.name = data.get('name', item.name)
    item.description = data.get('description', item.description)
    item.quantity = data.get('quantity', item.quantity)
    item.price = data.get('price', item.price)
    db.session.commit()
    return jsonify(message="Inventory item updated successfully"), 200

@app.route('/inventory/<int:item_id>', methods=['DELETE'])
@login_required
def delete_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if item.user_id != int(session['_user_id']):
        return jsonify(message="Unauthorized access"), 403
    db.session.delete(item)
    db.session.commit()
    return jsonify(message="Inventory item deleted successfully"), 200

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
