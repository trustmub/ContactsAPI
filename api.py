#!/usr/bin/env python
import os
import datetime
from flask import Flask, abort, request, jsonify, g, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

# initialization
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contacts2.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class Contacts(db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    phone = db.Column(db.String(15))
    email = db.Column(db.String(50))
    update_date = db.Column(db.DateTime)
    create_date = db.Column(db.DateTime)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', backref=db.backref('contacts', lazy='dynamic'))

    def __init__(self, name, phone, email, user_id, update_date, create_date=None):
        self.name = name
        self.phone = phone
        self.email = email
        self.user_id = user_id
        self.update_date = update_date
        if create_date is None:
            create_date = datetime.datetime.utcnow()
        self.create_date = create_date

    def __str__(self):
        return self.name

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'phone': self.phone,
            'email': self.email,
            'create_date': self.create_date,
            'user_id': self.user_id
        }


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=20000):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        return user


@auth.verify_password
def verify_password(username_or_token, password):
    print(username_or_token)
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token.lower()).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username').lower()
    password = request.json.get('password')
    if username is None or password is None:
        print("username and password plank")
        abort(400)  # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        print(f"user exists ")
        return jsonify({'message': 'user already exists', 'status': 403}), 200
        # abort(403)  # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/delete/<int:id>')
def delete_contact(id):
    if Contacts.query.get(id):
        contact = Contacts.query.filter_by(id=id).first()
        print(contact.name)
        db.session.delete(contact)
        db.session.commit()
        return jsonify({'message': 'Record Deleted'}), 200
    else:
        print('no contact found')
        return jsonify({'message': 'Record not found'}), 200


@app.route('/api/token', methods=['get'])
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(20000)
    return jsonify({'token': token.decode('ascii'), 'duration': 20000})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


@app.route('/api/contacts', methods=['POST'])
@auth.login_required
def new_contact():
    name = request.json.get('name')
    phone = request.json.get('phone')
    email = request.json.get('email')
    update_date = datetime.datetime.now()
    user = g.user.id
    print(user)
    new_record = Contacts(name=name,
                          phone=phone,
                          email=email,
                          update_date=update_date,
                          user_id=user)
    db.session.add(new_record)
    db.session.commit()
    print("After Committing the record")
    return jsonify(new_record.serialize), 201


@app.route('/api/all/contacts', methods=['GET'])
@auth.login_required
def my_contacts():
    print(g.user.id)
    records = Contacts.query.filter_by(user_id=g.user.id).all()
    # print(records)
    return jsonify([record.serialize for record in records])


if __name__ == '__main__':
    if not os.path.exists('contacts2.sqlite'):
        db.create_all()
    app.run(host='0.0.0.0', debug=True, port=5001)
