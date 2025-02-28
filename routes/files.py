from flask import Blueprint, render_template, request, jsonify, session, send_from_directory
from extensions import db
from models.user import User
from models.file import File
import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_MIME_TYPES = {'application/pdf', 'image/png', 'image/jpeg', 'image/gif'}
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

files_bp = Blueprint('files', __name__, url_prefix='/apps/files')

def allowed_file(filename):
    """Check if the file has an allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@files_bp.route('/')
def files():
    """Render files page with only the logged-in user's uploaded files"""
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    # Fetch only the files uploaded by the logged-in user
    user_files = File.query.filter_by(user_id=current_user.id).order_by(File.uploaded_at.desc()).all()

    return render_template('files.html', files=user_files, current_user_id=current_user.id)


@files_bp.route('/upload', methods=['POST'])
def upload_file():
    """Handle secure file upload with restrictions"""
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    file = request.files.get('file')
    if not file:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    filename = secure_filename(file.filename)

    # Validate file extension
    if not allowed_file(filename):
        return jsonify({'success': False, 'error': 'File type not allowed'}), 400

    # Validate MIME type
    if file.mimetype not in ALLOWED_MIME_TYPES:
        return jsonify({'success': False, 'error': 'Invalid file type'}), 400

    # Save the file
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        file.save(file_path)

        new_file = File(
            filename=filename,
            file_path=file_path,
            user_id=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()

        return jsonify({'success': True, 'message': 'File uploaded successfully!', 'file': new_file.to_dict()})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@files_bp.route('/delete/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a file"""
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    file = File.query.get_or_404(file_id)

    if file.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    file_path = file.file_path

    db.session.delete(file)
    db.session.commit()

    if os.path.exists(file_path):
        os.remove(file_path)

    return jsonify({'success': True, 'message': 'File deleted successfully'})

@files_bp.route('/download/<int:file_id>')
def download_file(file_id):
    """Allow users to download only their own files"""
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    file = File.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    if not os.path.exists(file.file_path):
        return jsonify({'success': False, 'error': 'File not found on server'}), 404

    return send_from_directory(os.path.dirname(file.file_path), os.path.basename(file.file_path), as_attachment=True)

@files_bp.route('/uploads/<filename>')
def get_uploaded_file(filename):
    """Allow users to access only their own uploaded files"""
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    file = File.query.filter_by(filename=filename, user_id=current_user.id).first()
    if not file:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    if not os.path.exists(file.file_path):
        return jsonify({'success': False, 'error': 'File does not exist'}), 404

    return send_from_directory(UPLOAD_FOLDER, filename)

