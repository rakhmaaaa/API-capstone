from flask import Flask, render_template, request, make_response, current_app, jsonify, send_file
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from flask_restx import Resource, Api, reqparse
from pymongo import MongoClient
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from flask_restful import reqparse
import jwt
from flask_cors import CORS
import os
import base64
import functools

# Inisialisasi Flask
app = Flask(__name__)
api = Api(app, title="SeeForMe")
CORS(app)
jwt_manager = JWTManager(app)

# Konfigurasi MongoDB
app.config["MONGO_URI"] = 'mongodb://21090011:21090011@localhost:27017/21090011?authSource=auth'
mongo = PyMongo(app)
users_collection = mongo.db.users
history_collection = mongo.db.history
api_keys_collection = mongo.db.api_keys
# Konfigurasi Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = "seeformeappcapstone@gmail.com"
app.config['MAIL_PASSWORD'] = "fpcgplcjroejlnyo"
mail = Mail(app)

# Konfigurasi Direktori Upload
UPLOAD_FOLDER = '/home/student/21090011/see4me/uploads/profile_pictures'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = "seeforme"

def api_key_required(func):
    @functools.wraps(func)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        if not api_key:
            return jsonify({"message": "API key is missing"}), 400
        
        valid_api_key = api_keys_collection.find_one({"api_key": api_key})
        if not valid_api_key:
            return jsonify({"message": "Invalid API key"}), 403

        return func(*args, **kwargs)
    return decorated_function

# Fungsi untuk memeriksa apakah token ada di dalam daftar hitam
def is_token_blacklisted(token):
    return api_keys_collection.find_one({"blacklisted_tokens": token}) is not None

# Parser untuk registrasi pengguna
registerParser = reqparse.RequestParser()
registerParser.add_argument('fullname', type=str, required=True, help='Fullname is required')
registerParser.add_argument('email', type=str, required=True, help='Email is required')
registerParser.add_argument('password', type=str, required=True, help='Password is required')
registerParser.add_argument('confirm_password', type=str, required=True, help='Confirm password is required')

# Endpoint untuk registrasi pengguna
@app.route('/user/register', methods=['POST'])
def register():
    args = request.get_json()
    fullname = args['fullname']
    email = args['email']
    password = args['password']
    confirm_password = args['confirm_password']

    if not all([fullname, email, password, confirm_password]):
        return jsonify({'message': 'Data tidak lengkap, pastikan semua field terisi.'}), 400

    if password != confirm_password:
        return jsonify({'message': 'Password tidak cocok, cek kembali passwordnya!'}), 400

    user = users_collection.find_one({"email": email})
    if user:
        return jsonify({'message': 'Email ini sudah terdaftar, gunakan email lain!'}), 400

    try:
        hashed_password = generate_password_hash(password)
        user_id = users_collection.insert_one({
            "fullname": fullname,
            "email": email,
            "password": hashed_password,
            "photo": None,
            "is_verify": False,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }).inserted_id

        jwt_secret_key = str(current_app.config.get("SECRET_KEY", "seeforme"))
        email_token = jwt.encode({"id": str(user_id)}, jwt_secret_key, algorithm="HS256")
        url = f"http://194.31.53.102:21011/verify-account/{email_token}"

        data = {
            'name': fullname,
            'url': url
        }
        sender = "seeformeappcapstone@gmail.com"
        msg = Message(subject="Verifikasi Email Anda - SeeForMe", sender=sender, recipients=[email])
        msg.html = render_template("verify-email.html", data=data)
        mail.send(msg)

        return jsonify({'message': "Berhasil membuat akun, cek email untuk verifikasi"}), 201
    except Exception as e:
        return jsonify({'message': f"Error {str(e)}"}), 500

@app.route('/verify-account/<token>', methods=['GET'])
def verify_email(token):
    try:
        jwt_secret_key = str(current_app.config.get("SECRET_KEY", "seeforme"))
        decoded_token = jwt.decode(str(token), key=jwt_secret_key, algorithms=["HS256"])
        user_id = decoded_token["id"]
        user = users_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return jsonify({"message": "User tidak ditemukan"}), 404

        if user.get("is_verify"):
            response = make_response(render_template('response.html', success=False, 
            message='Akun sudah diverifikasi sebelumnya'), 400)
            response.headers['Content-Type'] = 'text/html'
            return response

        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"is_verify": True}})

        response = make_response(render_template('response.html', success=True, 
        message='Akun berhasil diverifikasi'), 200)
        response.headers['Content-Type'] = 'text/html'
        return response

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token telah kadaluarsa"}), 401

    except (jwt.InvalidTokenError, KeyError):
        return jsonify({"message": "Token tidak valid"}), 401

    except Exception as e:
        return jsonify({"message": f"Error {str(e)}"}), 500

# Login Parser
loginParser = reqparse.RequestParser()
loginParser.add_argument('email', type=str, help='Email Address', required=True)
loginParser.add_argument('password', type=str, help='Password', required=True)

# Login
@app.route('/user/login', methods=['POST'])
@api_key_required
def login():
    base64Str = request.headers.get('Authorization')
    base64Str = base64Str[6:]

    base64Bytes = base64Str.encode('ascii')
    messageBytes = base64.b64decode(base64Bytes)
    pair = messageBytes.decode('ascii')

    email, password = pair.split(":")

    if not email or not password:
        return jsonify({"message": "Harap masukkan email dan password"}), 400

    user = users_collection.find_one({"email": email})

    if not user:
        return jsonify({"message": "User tidak ditemukan, silakan daftar"}), 400

    if not user.get("is_verify"):
        return jsonify({"message": "Akun belum aktif, cek email untuk verifikasi"}), 401

    if check_password_hash(user["password"], password):
        payload = {
            'id': str(user["_id"]),
            'fullname': str(user["fullname"]),
            'email': str(user["email"])
        }

        jwt_secret_key = str(current_app.config.get("SECRET_KEY", "seeforme"))
        token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")

        return jsonify({'token': token, 'status': 'success'}), 200
    else:
        return jsonify({'message': 'Password salah', 'status': 'failed'}), 400

@app.route('/user/current', methods=['GET'])
@api_key_required
def who_is_login():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if is_token_blacklisted(token):
        return jsonify({'message': 'Invalid token'}), 401

    try:
        decoded_token = jwt.decode(str(token), key="seeforme", algorithms=["HS256"])
        user_id = decoded_token["id"]
        user = users_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return jsonify({'message': 'User not found'}), 404

        return jsonify({
            'status': 'Success',
            'data': {
                'id': str(user["_id"]),
                'fullname': str(user["fullname"]),
                'email': str(user["email"])
            }
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token is expired'}), 401

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

# parser untuk update profile
updateProfileParser = reqparse.RequestParser()
updateProfileParser.add_argument('fullname', type=str, help='Full Name')
updateProfileParser.add_argument('photo', type=FileStorage, location='files', help='Profile Picture')

@app.route('/user/update_profile', methods=['PUT'])
def update_profile():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if is_token_blacklisted(token):
        return jsonify({'message': 'Invalid token'}), 401

    try:
        decoded_token = jwt.decode(str(token), key="seeforme", algorithms=["HS256"])
        user_id = decoded_token["id"]
        user = users_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return jsonify({"message": "Pengguna tidak ditemukan"}), 404

        if 'photo' not in request.files and 'fullname' not in request.form:
            return jsonify({"message": "Data permintaan tidak valid"}), 400

        updates = {}
        if 'photo' in request.files:
            photo = request.files['photo']
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"{timestamp}_{secure_filename(photo.filename)}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(save_path)
            updates['photo'] = filename

        if 'fullname' in request.form:
            updates['fullname'] = request.form['fullname']

        if updates:
            users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": updates})

        return jsonify({"message": "Berhasil update profil"}), 200

    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({"message": f"Error: {str(e)}"}), 500
        
# Forgot Password
forgotPasswordParser = reqparse.RequestParser()
forgotPasswordParser.add_argument('email', type=str, help='Email is required', required=True)

@app.route('/user/forgot-password', methods=['POST'])
@api_key_required
def forgot_password():
    args = forgotPasswordParser.parse_args()
    email = args['email']

    if not email:
        return jsonify({'message': 'Email tidak boleh kosong'}), 400

    user = users_collection.find_one({"email": email})

    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404

    try:
        jwt_secret_key = str(current_app.config.get("SECRET_KEY", "seeforme"))
        password_reset_token = jwt.encode({"id": str(user["_id"])}, jwt_secret_key, algorithm="HS256")
        url = f"http://194.31.53.102:21011/user/reset-password/{password_reset_token}"

        data = {
            'name': user['fullname'],
            'url': url
        }
        sender = "seeformeappcapstone@gmail.com"
        msg = Message(subject="Password Reset - SeeForMe", sender=sender, recipients=[email])
        msg.html = render_template("reset-password.html", data=data)
        mail.send(msg)

        return jsonify({'message': "Email untuk reset password telah dikirim"}), 200
    except Exception as e:
        return jsonify({'message': f"Error {str(e)}"}), 500

# Reset Password View
@api.route('/user/reset-password/<token>')
class ViewResetPassword(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="seeforme", algorithms=["HS256"])
            user_id = decoded_token["id"]
            
            # Assuming 'users_collection' is your MongoDB collection instance
            user = users_collection.find_one({"_id": ObjectId(user_id)})

            if not user:
                return {"message": "User not found"}, 404

            response = make_response(render_template('form-reset-password.html', id=str(user["_id"])), 200)
            response.headers['Content-Type'] = 'text/html'

            return response

        except jwt.exceptions.ExpiredSignatureError:
            return {"message": "Token has expired."}, 401

        except (jwt.exceptions.InvalidTokenError, KeyError):
            return {"message": "Invalid token."}, 401

        except Exception as e:
            return {"message": f"Error {e}"}, 500

# Reset Password Parser
resetPasswordParser = reqparse.RequestParser()
resetPasswordParser.add_argument('id', type=str, required=True, help='User ID is required')
resetPasswordParser.add_argument('password', type=str, required=True, help='New password is required')
resetPasswordParser.add_argument('confirmPassword', type=str, required=True, help='Confirm password is required')

# Reset Password
@api.route('/user/reset-password', methods=['PUT', 'POST'])
class ResetPassword(Resource):
    def post(self):
        # args = resetPasswordParser.parse_args()
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        user_id = request.form.get('id')

        try:
            user = users_collection.find_one({"_id": ObjectId(user_id)})

            if not user:
                return {'message': 'User not found'}, 404

            if password != confirm_password:
                return {'message': 'Passwords do not match'}, 400

            hashed_password = generate_password_hash(password)
            users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"password": hashed_password}})

            response = make_response(render_template('response.html', success=True, message='Password has been reset successfully'), 200)
            response.headers['Content-Type'] = 'text/html'
            return response

        except Exception as e:
            return {'message': f"Error {str(e)}"}, 500

# Change Password
changePasswordParser = reqparse.RequestParser()
changePasswordParser.add_argument('current_password', type=str, help='Current password is required', required=True)
changePasswordParser.add_argument('new_password', type=str, help='New password is required', required=True)
changePasswordParser.add_argument('confirm_password', type=str, help='Confirm password is required', required=True)

@app.route('/user/change-password', methods=['PUT'])
@api_key_required
def change_password():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if is_token_blacklisted(token):
        return jsonify({'message': 'Token tidak valid'}), 401
    
    args = changePasswordParser.parse_args()
    current_password = args['current_password']
    new_password = args['new_password']
    confirm_password = args['confirm_password']

    if not current_password or not new_password or not confirm_password:
        return jsonify({'message': 'Password tidak boleh kosong'}), 400

    if new_password != confirm_password:
        return jsonify({'message': 'Password tidak cocok, cek kembali passwordnya!'}), 400

    try:
        jwt_secret_key = str(current_app.config.get("SECRET_KEY", "seeforme"))
        decoded_token = jwt.decode(str(token), key=jwt_secret_key, algorithms=["HS256"])
        user_id = decoded_token["id"]
        user = users_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return jsonify({'message': 'User tidak ditemukan'}), 404

        if not check_password_hash(user["password"], current_password):
            return jsonify({'message': 'Password saat ini salah'}), 400

        hashed_password = generate_password_hash(new_password)
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"password": hashed_password, 
        "updated_at": datetime.utcnow()}})

        return jsonify({'message': 'Password berhasil diubah'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token telah kadaluarsa'}), 401

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Token tidak valid'}), 401

    except Exception as e:
        return jsonify({'message': f"Error {str(e)}"}), 500

# Logout
logoutParser = reqparse.RequestParser()
logoutParser.add_argument('token', type=str, help='Token is required', required=True)

@app.route('/logout', methods=['POST'])
@api_key_required
def logout():
    args = logoutParser.parse_args()
    token = args['token']

    if not token:
        return jsonify({'message': 'Token tidak boleh kosong'}), 400

    try:
        jwt.decode(str(token), key="seeforme", algorithms=["HS256"])
        blacklist_token(token)
        return jsonify({'message': 'User berhasil logout'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token telah kadaluarsa'}), 401

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Token tidak valid'}), 401

@app.route('/user/image/<image_name>', methods=["GET"])
def get_image(image_name):
    return send_file(f"/home/student/21090011/see4me/uploads/profile_pictures/{image_name}", mimetype="image/jpeg")


# Menjalankan Flask App
if __name__ == '__main__':
    app.config['UPLOAD_FOLDER'] = 'uploads/profile_pictures'
    app.config['SECRET_KEY'] = "seeforme"
    app.run(debug=True)
