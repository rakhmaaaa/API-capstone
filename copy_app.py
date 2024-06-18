from flask import Flask, render_template, request, make_response, current_app
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from datetime import datetime
import jwt
from flask_cors import CORS
import base64
import os

# Inisialisasi Flask
app = Flask(__name__)
api = Api(app, title="SeeForMe")
CORS(app)

# Konfigurasi SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/seeforme'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'rakhma1311'
db = SQLAlchemy(app)

# Konfigurasi Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = "seeformeappcapstone@gmail.com"
app.config['MAIL_PASSWORD'] = "fpcgplcjroejlnyo"
mail = Mail(app)

# Konfigurasi Upload Folder
app.config['UPLOAD_FOLDER'] = 'uploads/profile_pictures'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Buat folder upload jika belum ada
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Definisi Model Database
class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    fullname = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(64), nullable=False, unique=True)
    password = db.Column(db.String(1000), nullable=False)
    is_verify = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    profile_picture = db.Column(db.String(256), nullable=True)

# Buat tabel jika belum ada
# @app.before_first_request
# def create_tables():
#     db.create_all()

# Parser untuk registrasi pengguna
registerParser = reqparse.RequestParser()
registerParser.add_argument('fullname', type=str, required=True, help='Fullname is required')
registerParser.add_argument('email', type=str, required=True, help='Email is required')
registerParser.add_argument('password', type=str, required=True, help='Password is required')
registerParser.add_argument('confirm_password', type=str, required=True, help='Confirm password is required')

# Endpoint untuk registrasi pengguna
@api.route('/user/register')
class Registration(Resource):
    @api.expect(registerParser)
    def post(self):
        args = registerParser.parse_args()
        fullname = args['fullname']
        email = args['email']
        password = args['password']
        confirm_password = args['confirm_password']

        # Cek apakah semua data tersedia
        if not all([fullname, email, password, confirm_password]):
            return {'message': 'Data tidak lengkap, pastikan semua field terisi.'}, 400

        # Pastikan password sesuai dengan konfirmasi password
        if password != confirm_password:
            return {'message': 'Password tidak cocok, cek kembali passwordnya!'}, 400

        # Cek apakah email sudah terdaftar
        user = Users.query.filter_by(email=email).first()
        if user:
            return {'message': 'Email ini sudah terdaftar, gunakan email lain!'}, 400

        try:
            # Buat objek pengguna baru
            hashed_password = generate_password_hash(password)
            user = Users(fullname=fullname, email=email, password=hashed_password, is_verify=False)
            db.session.add(user)
            db.session.commit()

            # Kirim email verifikasi
            user_id = user.id
            jwt_secret_key = current_app.config.get("SECRET_KEY", "seeforme")
            email_token = jwt.encode({"id": user_id}, jwt_secret_key, algorithm="HS256")
            url = f"https://c264-103-166-147-253.ngrok-free.app/user/verify-account/{email_token}"

            data = {
                'name': fullname,
                'url': url
            }
            sender = "seeformeappcapstone@gmail.com"
            msg = Message(subject="Verify Your Email - SeeForMe", sender=sender, recipients=[email])
            msg.html = render_template("verify-email.html", data=data)
            mail.send(msg)

            return {'message': "Berhasil membuat akun, cek email untuk verifikasi"}, 201
        except Exception as e:
            return {'message': f"Error {str(e)}"}, 500

# Endpoint untuk verifikasi email
@api.route('/user/verify-account/<token>')
class VerifyEmail(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key=current_app.config.get("SECRET_KEY", "seeforme"), algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = Users.query.filter_by(id=user_id).first()

            if not user:
                return {"message": "User tidak ditemukan"}, 404

            if user.is_verify:
                response = make_response(render_template('response.html', success=False, message='Akun sudah diverifikasi sebelumnya'), 400)
                response.headers['Content-Type'] = 'text/html'
                return response

            user.is_verify = True
            db.session.commit()

            response = make_response(render_template('response.html', success=True, message='Akun berhasil diverifikasi'), 200)
            response.headers['Content-Type'] = 'text/html'
            return response

        except jwt.ExpiredSignatureError:
            return {"message": "Token telah kadaluarsa"}, 401

        except (jwt.InvalidTokenError, KeyError):
            return {"message": "Token tidak valid"}, 401

        except Exception as e:
            return {"message": f"Error {str(e)}"}, 500

# Login
@api.route('/user/login')
class Login(Resource):
    def post(self):
        base64Str = request.headers.get('Authorization')
        base64Str = base64Str[6:]
        
        base64Bytes = base64Str.encode('ascii')
        messageBytes = base64.b64decode(base64Bytes)
        pair = messageBytes.decode('ascii')
        
        email, password = pair.split(":")
        
        if not email or not password:
            return {"message": "Harap masukkan email dan password"}, 400
        
        user = Users.query.filter_by(email=email).first()
        
        if not user:
            return {"message": "User tidak ditemukan, silakan daftar"}, 400
        
        if not user.is_verify:
            return {"message": "Akun belum aktif, cek email untuk verifikasi"}, 401
        
        if check_password_hash(user.password, password):
            payload = {
                'id': user.id,
                'fullname': user.fullname,
                'email': user.email
            }
        
            jwt_secret_key = current_app.config.get("SECRET_KEY", "seeforme")
            token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
            
            return { 
                    'token': token,
                    'status': 'success'}, 200
        else:
            return { 
                    'message': 'Password salah',
                    'status': 'failed' 
                    }, 400

# User is currently logged in
@api.route('/user/current')
class WhoIsLogin(Resource):
    def get(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        try:
            decoded_token = jwt.decode(token, key="seeforme", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(Users).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404
            
            user = user[0]
            
            return {
                'status': 'Success',
                'data': {
                    'id': user.id,
                    'fullname': user.fullname,
                    'email': user.email
                }
            }, 200
        
        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401
        
        except jwt.InvalidTokenError:
            return {'messge': 'Invalid token'}, 401

# Parser untuk update pengguna
updateUserParser = reqparse.RequestParser()
updateUserParser.add_argument('fullname', type=str, required=False, help='Fullname is optional')
updateUserParser.add_argument('email', type=str, required=False, help='Email is optional')
updateUserParser.add_argument('profile_picture', type=FileStorage, location='files', required=False, help='Profile picture is optional')

# Endpoint untuk memperbarui pengguna
@api.route('/user/update')
class UpdateUser(Resource):
    @api.expect(updateUserParser)
    def put(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            decoded_token = jwt.decode(token, key="seeforme", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = Users.query.filter_by(id=user_id).first()

            if user is None:
                return {'message': 'User not found'}, 404

            args = updateUserParser.parse_args()
            new_email = args.get('email')
            fullname = args.get('fullname')
            profile_picture = args.get('profile_picture')

            if new_email and user.email != new_email:
                # Email berubah, kirim email konfirmasi
                jwt_secret_key = current_app.config.get("SECRET_KEY", "seeforme")
                email_token = jwt.encode({"id": user_id, "new_email": new_email}, jwt_secret_key, algorithm="HS256")
                url = f"https://c39a-103-158-253-152.ngrok-free.app/user/confirm-email/{email_token}"
                
                data = {
                    'name': user.fullname,
                    'url': url
                }
                
                sender = "seeformeappcapstone@gmail.com"
                msg = Message(subject="Confirm Your New Email - SeeForMe", sender=sender, recipients=[new_email])
                msg.html = render_template("confirm-email.html", data=data)
                
                try:
                    mail.send(msg)
                    return {'message': 'Check your new email to confirm the update'}, 200
                except Exception as e:
                    return {'message': f"Failed to send confirmation email: {str(e)}"}, 500
            
            if fullname:
                user.fullname = fullname

            if profile_picture and allowed_file(profile_picture.filename):
                filename = secure_filename(profile_picture.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_picture.save(filepath)
                user.profile_picture = filepath
            
            db.session.commit()
            return {'message': 'Profile updated successfully'}, 200
            
        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401
        except Exception as e:
            return {'message': f"Error {str(e)}"}, 500

# Endpoint untuk mengkonfirmasi email baru
@api.route('/user/confirm-email/<token>')
class ConfirmEmail(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key=current_app.config.get("SECRET_KEY", "seeforme"), algorithms=["HS256"])
            user_id = decoded_token["id"]
            new_email = decoded_token["new_email"]

            user = Users.query.filter_by(id=user_id).first()
            if user is None:
                return {"message": "User not found"}, 404

            user.email = new_email
            db.session.commit()
            
            response = make_response(render_template('response.html', success=True, message='Email berhasil diperbarui'), 200)
            response.headers['Content-Type'] = 'text/html'
            return response

        except jwt.ExpiredSignatureError:
            return {"message": "Token has expired"}, 401

        except (jwt.InvalidTokenError, KeyError):
            return {"message": "Invalid token"}, 401

        except Exception as e:
            return {"message": f"Error {str(e)}"}, 500

if __name__ == '__main__':
    app.run(debug=True)
