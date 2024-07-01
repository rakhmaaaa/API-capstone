from flask import Flask, render_template, request, make_response, current_app, jsonify
from flask import jsonify
from flask_restx import Resource, Api, reqparse
from pymongo import MongoClient
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from datetime import datetime, timedelta
import jwt
from flask_cors import CORS
import os
import cloudinary
import cloudinary.uploader
import cloudinary.api
import base64
from bson.objectid import ObjectId
import functools

# Inisialisasi Flask
app = Flask(__name__)
api = Api(app, title="SeeForMe")
CORS(app)

# Konfigurasi MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['seeforme']
users_collection = db['users']
history_collection = db['history']
api_keys_collection = db['api_keys']

# Konfigurasi Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = "seeformeappcapstone@gmail.com"
app.config['MAIL_PASSWORD'] = "fpcgplcjroejlnyo"
mail = Mail(app)

# Konfigurasi Cloudinary
cloudinary.config(
    cloud_name='dqoo6tunz',
    api_key='517427571893353',
    api_secret='l8NANM4gf4vBrb4Rqyxatnnq4i4'
)

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
@app.route('/register', methods=['POST'])
# @api_key_required
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
            url = f"https://5461-103-166-147-253.ngrok-free.app/verify-account/{email_token}"

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

# User Update Parser
updateUserParser = reqparse.RequestParser()
updateUserParser.add_argument('fullname', type=str, help='fullname', required=True)
updateUserParser.add_argument('photo', type=FileStorage, help='photo', location='files')

# Endpoint untuk memperbarui data pengguna
@app.route('/user/update', methods=['PUT'])
@api_key_required
def update_user():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if is_token_blacklisted(token):
        return jsonify({'message': 'Invalid token'}), 401

    try:
        jwt_secret_key = str(current_app.config.get("SECRET_KEY", "seeforme"))
        decoded_token = jwt.decode(str(token), key=jwt_secret_key, algorithms=["HS256"])
        user_id = decoded_token["id"]
        user = users_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return jsonify({'message': 'User not found'}), 404

        data = request.form
        file = request.files.get('photo')

        if not data and not file:
            return jsonify({'message': 'No data to update'}), 400

        update_data = {}

        if data:
            fullname = data.get('fullname')
            update_data['fullname'] = fullname

        if file:
            filename = secure_filename(file.filename)
            upload_result = cloudinary.uploader.upload(file)
            photo_url = upload_result.get("secure_url")
            update_data['photo'] = photo_url

        if update_data:
            update_data['updated_at'] = datetime.utcnow()
            users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})

        return jsonify({'status': 'success', 'message': 'User data updated successfully'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token is expired'}), 401

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    except Exception as e:
        return jsonify({'message': f"Error {str(e)}"}), 500

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
        url = f"https://5461-103-166-147-253.ngrok-free.app/user/reset-password/{password_reset_token}"

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

@app.route('/user/reset-password/<token>', methods=['GET'])
def view_reset_password(token):
    try:
        jwt_secret_key = str(current_app.config.get("SECRET_KEY", "seeforme"))
        decoded_token = jwt.decode(str(token), key=jwt_secret_key, algorithms=["HS256"])
        user_id = decoded_token["id"]
        user = users_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return jsonify({"message": "User tidak ditemukan"}), 404

        response = make_response(render_template('form-reset-password.html', id=user["_id"]), 200)
        response.headers['Content-Type'] = 'text/html'
        return response

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token telah kadaluarsa"}), 401

    except (jwt.InvalidTokenError, KeyError):
        return jsonify({"message": "Token tidak valid"}), 401

    except Exception as e:
        return jsonify({"message": f"Error {str(e)}"}), 500


# Reset Password
resetPasswordParser = reqparse.RequestParser()
resetPasswordParser.add_argument('new_password', type=str, help='New password is required', required=True)
resetPasswordParser.add_argument('confirm_password', type=str, help='Confirm password is required', required=True)

@app.route('/reset-password/<token>', methods=['POST'])
@api_key_required
def reset_password(token):
    args = resetPasswordParser.parse_args()
    new_password = args['new_password']
    confirm_password = args['confirm_password']

    if not new_password or not confirm_password:
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

        hashed_password = generate_password_hash(new_password)
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"password": hashed_password, 
        "updated_at": datetime.utcnow()}})

        response = make_response(render_template('response.html', success=True, 
        message='Password berhasil direset'), 200)
        response.headers['Content-Type'] = 'text/html'
        return response

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token telah kadaluarsa'}), 401

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Token tidak valid'}), 401

    except Exception as e:
        return jsonify({'message': f"Error {str(e)}"}), 500

# Change Password
changePasswordParser = reqparse.RequestParser()
changePasswordParser.add_argument('current_password', type=str, help='Current password is required', required=True)
changePasswordParser.add_argument('new_password', type=str, help='New password is required', required=True)
changePasswordParser.add_argument('confirm_password', type=str, help='Confirm password is required', required=True)

@app.route('/change-password', methods=['POST'])
@api_key_required
def change_password():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if is_token_blacklisted(token):
        return jsonify({'message': 'Invalid token'}), 401
    
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

# Menjalankan Flask App
if __name__ == '__main__':
    app.config['SECRET_KEY'] = "seeforme"
    app.run(debug=True)
