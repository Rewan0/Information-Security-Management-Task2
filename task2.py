from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
import jwt, datetime, os
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
SECRET_KEY = os.getenv("JWT_SECRET", "mysecretkey")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Product(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

with app.app_context():
    db.create_all()

# User Registration
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_password = generate_password_hash(data['password'])
    new_user = User(name=data['name'], username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered"})

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"error": "Invalid credentials"}), 400
    token = jwt.encode({'sub': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})

# Authentication Middleware
def authenticate():
    token = request.headers.get('Authorization')
    if not token:
        abort(401, "No token provided")
    try:
        jwt.decode(token.split(" ")[1], SECRET_KEY, algorithms=["HS256"])
    except:
        abort(401, "Invalid or expired token")

# Get All Users
@app.route('/users', methods=['GET'])
def get_users():
    authenticate()
    users = User.query.all()
    return jsonify([{ "id": u.id, "name": u.name, "username": u.username} for u in users])

# Update User Details
@app.route('/users/<int:id>', methods=['PUT'])
def update_user(id):
    authenticate()
    data = request.json
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user.name = data.get("name", user.name)
    db.session.commit()
    return jsonify({"message": "User updated successfully"})

# Add Product (Protected)
@app.route('/products', methods=['POST'])
def add_product():
    authenticate()
    data = request.json
    new_product = Product(pname=data['pname'], description=data.get('description', ''), price=data['price'], stock=data['stock'])
    db.session.add(new_product)
    db.session.commit()
    return jsonify({"message": "Product added"})

# Get All Products
@app.route('/products', methods=['GET'])
def get_products():
    authenticate()
    products = Product.query.all()
    return jsonify([{ "pid": p.pid, "pname": p.pname, "description": p.description, "price": p.price, "stock": p.stock, "created_at": p.created_at} for p in products])

# Get Single Product
@app.route('/products/<int:pid>', methods=['GET'])
def get_product(pid):
    authenticate()
    product = Product.query.get(pid)
    if not product:
        return jsonify({"error": "Product not found"}), 404
    return jsonify({"pid": product.pid, "pname": product.pname, "description": product.description, "price": product.price, "stock": product.stock, "created_at": product.created_at})

# Update Product
@app.route('/products/<int:pid>', methods=['PUT'])
def update_product(pid):
    authenticate()
    data = request.json
    product = Product.query.get(pid)
    if not product:
        return jsonify({"error": "Product not found"}), 404
    product.pname = data.get("pname", product.pname)
    product.description = data.get("description", product.description)
    product.price = data.get("price", product.price)
    product.stock = data.get("stock", product.stock)
    db.session.commit()
    return jsonify({"message": "Product updated successfully"})

# Delete Product
@app.route('/products/<int:pid>', methods=['DELETE'])
def delete_product(pid):
    authenticate()
    product = Product.query.get(pid)
    if not product:
        return jsonify({"error": "Product not found"}), 404
    db.session.delete(product)
    db.session.commit()
    return jsonify({"message": "Product deleted successfully"})

if __name__ == '__main__':
    app.run(debug=True)
