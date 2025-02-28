import re
import os
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    salt = db.Column(db.String(50), nullable=False, default="")  # ✅ Ensure salt is never None

    def set_password(self, password):
        """Validates and hashes the password with a unique salt before storing it."""
        if not self.is_valid_password(password):
            raise ValueError("Password must be at least 8 characters long, include 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character.")
        
        if not self.salt:  # ✅ Generate salt if not already set
            self.salt = self.generate_salt()
        
        salted_password = self.salt + password
        self.password_hash = generate_password_hash(salted_password)

    def check_password(self, password) -> bool:
        """Compares hashed password to user-provided password."""
        if not self.salt:  # ✅ Handle case where salt is missing
            print("Warning: User salt is missing, assuming empty string.")
            self.salt = ""

        salted_password = self.salt + password
        return check_password_hash(self.password_hash, salted_password)

    @staticmethod
    def is_valid_password(password):
        """Checks if password meets security requirements."""
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        return re.match(pattern, password) is not None

    @staticmethod
    def generate_salt():
        """Generates a cryptographically secure random salt."""
        return base64.b64encode(os.urandom(16)).decode('utf-8')

    def __repr__(self):
        return f"<User {self.username}>"

