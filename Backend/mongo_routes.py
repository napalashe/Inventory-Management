from flask import Blueprint, request, jsonify
from mongodb_config import user_collection, inventory_collection

mongo_routes = Blueprint("mongo_routes", __name__)

@mongo_routes.route('/mongo_register', methods=['POST'])
def mongo_register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    age = data.get('age')

    if user_collection.find_one({"email": email}):
        return jsonify({"message": "Email already exists"}), 400

    user_id = user_collection.insert_one({
        "username": username,
        "email": email,
        "password": password,
        "age": age
    }).inserted_id

    return jsonify({"message": "User registered successfully", "user_id": str(user_id)}), 201

@mongo_routes.route('/mongo_add_inventory', methods=['POST'])
def mongo_add_inventory():
    data = request.json
    name = data.get('name')
    description = data.get('description')
    quantity = data.get('quantity')
    price = data.get('price')

    item_id = inventory_collection.insert_one({
        "name": name,
        "description": description,
        "quantity": quantity,
        "price": price
    }).inserted_id

    return jsonify({"message": "Inventory item added successfully", "item_id": str(item_id)}), 201

@mongo_routes.route('/mongo_get_inventory', methods=['GET'])
def mongo_get_inventory():
    items = list(inventory_collection.find({}, {"_id": 0}))
    return jsonify(items), 200

@mongo_routes.route('/mongo_get_users', methods=['GET'])
def mongo_get_users():
    users = list(user_collection.find({}, {"_id": 0}))
    return jsonify(users), 200

@mongo_routes.route('/mongo_create_index', methods=['POST'])
def mongo_create_index():
    data = request.json
    collection_name = data.get('collection')
    field = data.get('field')
    unique = data.get('unique', False)

    if collection_name == "users":
        collection = user_collection
    elif collection_name == "inventory":
        collection = inventory_collection
    else:
        return jsonify({"message": "Invalid collection name"}), 400

    index_name = collection.create_index([(field, 1)], unique=unique)
    return jsonify({"message": f"Index created: {index_name}"}), 201