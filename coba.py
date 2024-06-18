from flask import Flask, session, render_template, request, send_file, Response, current_app, make_response, jsonify
# from flask_restx import Resource, Api, reqparse
# from flask_cors import CORS
# from flask_sqlalchemy import SQLAlchemy
# from flask_mail import Mail, Message
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime, timedelta
# from flask import Blueprint
# import random
# import pymysql
# import jwt
# import os
# import base64

# # Inisialisasi Flask
# app = Flask(__name__)
# CORS(app)

# # Konfigurasi SQLAlchemy
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/seeforme'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SECRET_KEY'] = 'rakhma1311'
# db = SQLAlchemy(app)

# # Konfigurasi Mail
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 465
# app.config['MAIL_USE_SSL'] = True
# app.config['MAIL_USERNAME'] = "seeformeappcapstone@gmail.com"
# app.config['MAIL_PASSWORD'] = "fpcgplcjroejlnyo"
# mail = Mail(app)

# # Definisi Model Database
# class Users(db.Model):
#     __tablename__ = 'users'
#     id = db.Column(db.Integer, primary_key=True, nullable=False)
#     fullname = db.Column(db.String(30), nullable=False)
#     email = db.Column(db.String(64), nullable=False, unique=True)
#     password = db.Column(db.String(1000), nullable=False)
#     is_verify = db.Column(db.Boolean, default=False)
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#     updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# # Buat tabel jika belum ada
# # @app.before_first_request
# # def create_tables():
# #     db.create_all()

# # Inisialisasi Flask-Restx API
# api_blueprint = Blueprint('api', __name__)
# api = Api(api_blueprint)

# # Endpoint untuk registrasi pengguna
# @app.route('/register', methods=['POST'])
# def register_user():
#     # Ambil data dari request
#     data = request.get_json()
#     fullname = data.get('fullname')
#     email = data.get('email')
#     password = data.get('password')
#     confirm_password = data.get('confirm_password')

#     # Cek apakah semua data tersedia
#     if not all([fullname, email, password, confirm_password]):
#         return jsonify({'message': 'Data tidak lengkap, pastikan semua field terisi.'}), 400
    
#     # Encode Password dan Email menggunakan base64
#     encoded_password = base64.b64encode(password.encode('utf-8')).decode('utf-8')
#     encoded_confirm_password = base64.b64encode(confirm_password.encode('utf-8')).decode('utf-8')
#     encoded_email = base64.b64encode(email.encode('utf-8')).decode('utf-8')


#     # Pastikan password sesuai dengan konfirmasi password
#     if password != confirm_password:
#         return jsonify({'message': 'Password does not match, check the password again!'}), 400

#     # Cek apakah email sudah terdaftar
#     user = Users.query.filter_by(email=email).first()
#     if user:
#         return jsonify({'message': 'This email is already registered, please use another email!'}), 400

#     try:
#         # Buat objek pengguna baru
#         hashed_password = generate_password_hash(password)
#         user = Users(fullname=fullname, email=email, password=hashed_password, is_verify=False)
#         db.session.add(user)
#         db.session.commit()

#         # Kirim email verifikasi
#         user_id = user.id
#         jwt_secret_key = current_app.config.get("SECRET_KEY", "seeforme")
#         email_token = jwt.encode({"id": user_id}, jwt_secret_key, algorithm="HS256")
#         url = f"https://e9e2-103-158-253-156.ngrok-free.app/user/verify-account/{email_token}"

#         data = {
#             'name': fullname,
#             'url': url
#         }
#         sender = "seeformeappcapstone@gmail.com"
#         msg = Message(subject="Verify Your Email - SeeForMe", sender=sender, recipients=[email])
#         msg.html = render_template("verify-email.html", data=data)
#         mail.send(msg)

#         return jsonify({'message': "Success create account, check email to verify"}), 201
#     except Exception as e:
#         return jsonify({'message': f"Error {str(e)}"}), 500

# # Verify Email with Token
# @api.route('/user/verify-account/<token>')
# class VerifyEmail(Resource):
#     def get(self, token):
#         try:
#             jwt_secret_key = current_app.config.get("SECRET_KEY", "seeforme")
#             decoded_token = jwt.decode(token, key=jwt_secret_key, algorithms=["HS256"])
#             user_id = decoded_token["id"]
#             user = db.session.execute(db.select(Users).filter_by(id=user_id)).first()[0]

#             if not user:
#                 return {"message": "User not found"}, 404

#             if user.is_verify:
#                 response = make_response(render_template('response.html', success=False, message='Account has been verified'), 400)
#                 response.headers['Content-Type'] = 'text/html'
#                 return response

#             user.is_verify = True
#             db.session.commit()

#             response = make_response(render_template('response.html', success=True, message='Account has been verified'), 200)
#             response.headers['Content-Type'] = 'text/html'
#             return response

#         except jwt.ExpiredSignatureError:
#             return {"message": "Token has expired"}, 401

#         except (jwt.InvalidTokenError, KeyError):
#             return {"message": "Invalid token"}, 401

#         except Exception as e:
#             return {"message": f"Error {str(e)}"}, 500

# # Daftarkan Blueprint API
# app.register_blueprint(api_blueprint, url_prefix='/api')

# if __name__ == '__main__':
#     app.run(debug=True)