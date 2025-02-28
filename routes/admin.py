from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from models.admin import Admin
from extensions import db

admin_bp = Blueprint("admin", __name__)

DEFAULT_ADMIN = {
    "username": "admin",
    "password": "password"  # Default password (must be changed)
}

# 🛠️ Function to enforce strong password policies
def is_strong_password(password):
    """Checks if a password meets the security requirements."""
    return (
        len(password) >= 8 and  
        any(c.isupper() for c in password) and  
        any(c.isdigit() for c in password) and  
        any(c in "!@#$%^&*()-_=+" for c in password)  
    )

# 🛠️ Ensure admin exists at startup
def init_admin():
    """Ensure the default admin exists and has the correct password policy."""
    admin_user = User.query.filter_by(username=DEFAULT_ADMIN["username"]).first()
    
    if not admin_user:
        hashed_password = generate_password_hash(DEFAULT_ADMIN["password"])
        admin_user = User(username=DEFAULT_ADMIN["username"], password_hash=hashed_password)
        db.session.add(admin_user)
        db.session.commit()

    admin_role = Admin.query.filter_by(user_id=admin_user.id).first()
    if not admin_role:
        admin_role = Admin(user_id=admin_user.id, is_default=True)
        db.session.add(admin_role)
        db.session.commit()

# 🛠️ Route: Admin Login
@admin_bp.route("/admin", methods=["GET", "POST"])
def admin():
    """Admin login with default password change enforcement."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            admin_role = Admin.query.filter_by(user_id=user.id).first()
            
            if admin_role:
                session['admin_logged_in'] = True
                session['admin_username'] = username
                session['is_default_admin'] = admin_role.is_default

                # If the user is logging in with the default admin credentials, force a password change
                if username == DEFAULT_ADMIN["username"] and check_password_hash(user.password_hash, DEFAULT_ADMIN["password"]):
                    return redirect(url_for("admin.change_password"))

                return jsonify({'success': True, 'is_default_admin': admin_role.is_default})
        
        return jsonify({'success': False, 'message': "Invalid admin credentials."})
    
    return render_template("admin.html", is_default_admin=session.get('is_default_admin', False))

# 🛠️ Route: Change Admin Password (Forced for Default Admin)
@admin_bp.route("/admin/change-password", methods=["GET", "POST"])
def change_password():
    """Force admin to change default password before continuing."""
    if 'admin_logged_in' not in session or session.get("admin_username") != DEFAULT_ADMIN["username"]:
        return jsonify({'success': False, 'error': "Unauthorized"}), 403

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not new_password or not confirm_password:
            return jsonify({'success': False, 'error': "Both fields are required."}), 400

        if new_password != confirm_password:
            return jsonify({'success': False, 'error': "Passwords do not match."}), 400

        if not is_strong_password(new_password):
            return jsonify({'success': False, 'error': "Password must contain 8+ characters, an uppercase letter, a number, and a special character."}), 400

        user = User.query.filter_by(username=session["admin_username"]).first()
        if not user:
            return jsonify({'success': False, 'error': "Admin user not found."}), 404

        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'success': True, 'message': "Password changed successfully. Please log in again."})
    
    return render_template("change_password.html")

# 🛠️ Route: Add a New Admin (Only by Another Admin)
@admin_bp.route("/admin/add", methods=["POST"])
def add_admin():
    """Add a new admin user (only an existing admin can do this)."""
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'error': "Unauthorized"}), 403

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return jsonify({'success': False, 'error': "Missing credentials"}), 400

    if not is_strong_password(password):
        return jsonify({'success': False, 'error': "Weak password"}), 400

    user = User.query.filter_by(username=username).first()
    
    if not user:
        hashed_password = generate_password_hash(password)
        user = User(username=username, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
    
    existing_admin = Admin.query.filter_by(user_id=user.id).first()
    if existing_admin:
        return jsonify({'success': False, 'error': "User is already an admin"}), 400

    new_admin = Admin(user_id=user.id, is_default=False)
    db.session.add(new_admin)
    db.session.commit()

    return jsonify({'success': True, 'message': "Admin added successfully"})

# 🛠️ Route: Remove an Admin
@admin_bp.route("/admin/remove/<int:admin_id>", methods=["POST"])
def remove_admin(admin_id):
    """Remove an admin user (except the default admin)."""
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'error': "Unauthorized"}), 403

    admin = Admin.query.get(admin_id)
    if not admin:
        return jsonify({'success': False, 'error': "Admin not found"}), 404

    if admin.is_default:
        return jsonify({'success': False, 'error': "Cannot remove default admin"}), 400

    db.session.delete(admin)
    db.session.commit()

    return jsonify({'success': True, 'message': "Admin removed successfully"})

# 🛠️ Route: View All Users
@admin_bp.route("/admin/users", methods=["GET"])
def get_users():
    """Get list of all users."""
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'error': "Unauthorized"}), 403

    users = User.query.all()
    return jsonify({'success': True, 'users': [{'id': u.id, 'username': u.username} for u in users]})

# 🛠️ Route: Logout Admin
@admin_bp.route('/admin/logout', methods=['POST'])
def logout():
    """Logs out the admin"""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session.pop('is_default_admin', None)
    return jsonify({"success": True, "message": "Logged out successfully"})
