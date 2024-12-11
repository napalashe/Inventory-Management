from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")
mongo_db = client["flask_project_mongo"]
user_collection = mongo_db["users"]
inventory_collection = mongo_db["inventory"]

user_collection.create_index("email", unique=True)  
inventory_collection.create_index("name")  
