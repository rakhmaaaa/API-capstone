from flask import Flask, render_template, request, make_response, current_app
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
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

# Inisialisasi Flask
app = Flask(__name__)
api = Api(app, title="SeeForMe")
CORS(app)

# Konfigurasi SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/seeforme'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'seeforme'
db = SQLAlchemy(app)

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

# Definisi Model Database
class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    fullname = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(64), nullable=False, unique=True)
    password = db.Column(db.String(1000), nullable=False)
    photo = db.Column(db.String(1000), nullable=True)
    is_verify = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    token = db.Column(db.String(500), nullable=False, unique=True)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

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

        if not all([fullname, email, password, confirm_password]):
            return {'message': 'Data tidak lengkap, pastikan semua field terisi.'}, 400

        if password != confirm_password:
            return {'message': 'Password tidak cocok, cek kembali passwordnya!'}, 400

        user = Users.query.filter_by(email=email).first()
        if user:
            return {'message': 'Email ini sudah terdaftar, gunakan email lain!'}, 400

        try:
            hashed_password = generate_password_hash(password)
            user = Users(fullname=fullname, email=email, password=hashed_password, is_verify=False)
            db.session.add(user)
            db.session.commit()

            user_id = user.id
            jwt_secret_key = current_app.config.get("SECRET_KEY", "seeforme")
            email_token = jwt.encode({"id": user_id}, jwt_secret_key, algorithm="HS256")
            url = f"https://7c0c-103-158-253-159.ngrok-free.app/user/verify-account/{email_token}"

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

# Login Parser
loginParser = reqparse.RequestParser()
loginParser.add_argument('email', type=str, help='Email Address', required=True)
loginParser.add_argument('password', type=str, help='Password', required=True)

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

        if is_token_blacklisted(token):
            return {'message': 'Invalid token'}, 401

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
            return {'message': 'Invalid token'}, 401

# User Update Parser
updateUserParser = reqparse.RequestParser()
updateUserParser.add_argument('fullname', type=str, help='fullname', required=True)
updateUserParser.add_argument('photo', type=FileStorage, location='files', help='photo', required=False)

# User Profile Update
@api.route('/user/update')
class UpdateUser(Resource):
    @api.expect(updateUserParser)
    def put(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if is_token_blacklisted(token):
            return {'message': 'Invalid token'}, 401

        try:
            decoded_token = jwt.decode(token, key="seeforme", algorithms=["HS256"])
            user_id = decoded_token["id"]

            user = db.session.execute(db.select(Users).filter_by(id=user_id)).first()
            user = user[0]

            args = updateUserParser.parse_args()
            user.fullname = args["fullname"]

            if "photo" in args:
                user.photo = upload_result["url"]

            try:
                db.session.commit()
                return {'message': 'Profile update successfully'}, 200
            except:
                db.session.rollback()
                return {'message': 'Profile update failed'}, 400

        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401

# Forgot Password Parser
forgotPasswordParser = reqparse.RequestParser()
forgotPasswordParser.add_argument('email', type=str, help='Email Address', required=True)

# Forgot Password
@api.route('/user/forgot-password')
class ForgetPassword(Resource):
    @api.expect(forgotPasswordParser)
    def post(self):
        try:
            args = forgotPasswordParser.parse_args()
            email = args['email']

            user = db.session.execute(db.select(Users).filter_by(email=email)).first()

            if not user:
                return {'message': 'Email does not match any user'}, 404

            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "seeforme")

            email_token = jwt.encode({"id": user[0].id}, jwt_secret_key, algorithm="HS256")

            url = f"https://7c0c-103-158-253-159.ngrok-free.app/user/reset-password/{email_token}"

            sender = "seeformeappcapstone@gmail.com"
            msg = Message(subject="Reset your password", sender=sender, recipients=[email])
            msg.html = render_template("reset-password.html", url=url)

            mail.send(msg)
            return {'message': "Success send request, check email to verify"}, 200

        except Exception as e:
            return {"message": f"Error {e}"}, 500

# Reset Password View
@api.route('/user/reset-password/<token>')
class ViewResetPassword(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="seeforme", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(Users).filter_by(id=user_id)).first()

            if not user:
                return {"message": "User not found"}, 404

            response = make_response(render_template('form-reset-password.html', id=user[0].id), 200)
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
resetPasswordParser.add_argument('id', type=int, required=True, help='User ID is required')
resetPasswordParser.add_argument('password', type=str, required=True, help='New password is required')
resetPasswordParser.add_argument('confirmPassword', type=str, required=True, help='Confirm password is required')

# Reset Password
@api.route('/user/reset-password', methods=['PUT', 'POST'])
class ResetPassword(Resource):
    def post(self):
        args = resetPasswordParser.parse_args()
        password = args['password']
        user_id = args['id']

        user = db.session.execute(db.select(Users).filter_by(id=user_id)).first()
        if not user:
            return {'message': 'User not found'}, 404

        if password != args['confirmPassword']:
            return {'message': 'Passwords do not match'}, 400

        user[0].password = generate_password_hash(password)

        try:
            db.session.commit()
            response = make_response(render_template('response.html', success=True, message='Password has been reset successfully'), 200)
            response.headers['Content-Type'] = 'text/html'
            return response

        except:
            db.session.rollback()
            response = make_response(render_template('response.html', success=False, message='Reset password failed'), 400)
            response.headers['Content-Type'] = 'text/html'
            return response

# Change Password Parser
changePasswordParser = reqparse.RequestParser()
changePasswordParser.add_argument('oldPassword', type=str, required=True, help='Old password is required')
changePasswordParser.add_argument('password', type=str, required=True, help='New password is required')
changePasswordParser.add_argument('confirmPassword', type=str, required=True, help='Confirm password is required')

# Change Password
@api.route('/user/change-password')
class ChangePassword(Resource):
    @api.expect(changePasswordParser)
    def put(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if is_token_blacklisted(token):
            return {'message': 'Invalid token'}, 401

        args = changePasswordParser.parse_args()
        old_password = args['oldPassword']
        password = args['password']
        confirm_password = args['confirmPassword']

        try:
            decoded_token = jwt.decode(token, key="seeforme", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(Users).filter_by(id=user_id)).first()
            user = user[0]

            if check_password_hash(user.password, old_password):
                if password != confirm_password:
                    return {
                        'message': 'Password baru tidak cocok, cek kembali password nya!',
                    }, 400

                hashed_new_password = generate_password_hash(password)
                user.password = hashed_new_password
                db.session.commit()

                return {
                    'message': 'Berhasil mengubah password'
                }, 200
            else:
                return {'message': 'Password lama tidak sesuai'}, 401

        except Exception as e:
            return {
                'message': f"Error {e}"
            }, 401

# Logout
@api.route('/user/logout')
class Logout(Resource):
    def post(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        blacklisted_token = TokenBlacklist(token=token, blacklisted_on=datetime.utcnow())
        try:
            db.session.add(blacklisted_token)
            db.session.commit()
            response = make_response({'message': 'Logged out successfully'}, 200)
            response.headers['Content-Type'] = 'application/json'
            return response
        except Exception as e:
            return {
                'message': f"Error {e}"
            }, 500

def is_token_blacklisted(token):
    blacklist = TokenBlacklist.query.filter_by(token=token).first()
    return blacklist is not None

if __name__ == '__main__':
    # db.create_all()  # Buat tabel jika belum ada
    app.run(debug=True)
