# create_db.py — initialize tables and create admin user

import os
from getpass import getpass
from werkzeug.security import generate_password_hash
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from models import db, User

DB_URI = os.getenv("DATABASE_URL", "mysql+pymysql://root:password@localhost:3306/feedback_db")

def create_app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    return app

def main():
    app = create_app()
    with app.app_context():
        db.create_all()
        print("✔ Tables created successfully.")

        if input("Create admin user? (y/n): ").lower() == "y":
            name = input("Admin Name: ")
            email = input("Admin Email: ")
            password = getpass("Admin Password: ")
            hashed = generate_password_hash(password)
            admin = User(name=name, email=email, password=hashed, role="admin")
            db.session.add(admin)
            db.session.commit()
            print(f"✅ Admin user created: {email}")

if __name__ == "__main__":
    main()
