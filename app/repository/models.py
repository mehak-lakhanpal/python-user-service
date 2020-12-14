from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from marshmallow.validate import Length
from sqlalchemy import create_engine
from passlib.hash import sha256_crypt
from flask_marshmallow import Marshmallow
from marshmallow import Schema,fields, post_load

db = SQLAlchemy()

ma = Marshmallow()

def db_init_app(app):
    db.app = app
    db.init_app(app)
    return db

def ma_init_app(app):
    ma.app = app
    ma.init_app(app)
    return ma

def create_tables(app):
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
    db.metadata.create_all(engine)
    return engine


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    first_name = db.Column(db.String(255), unique=False, nullable=True)
    last_name = db.Column(db.String(255), unique=False, nullable=True)
    password = db.Column(db.String(255), unique=False, nullable=False)
    authenticated = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(255), unique=True, nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, default=datetime.utcnow,onupdate=datetime.utcnow)

    def encode_api_key(self):
        self.api_key = sha256_crypt.hash(self.username + str(datetime.utcnow))

    def encode_password(self):
        self.password = sha256_crypt.hash(self.password)

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def __repr__(self):
        return '<User %r>' %(self.username)

    def to_json(self):
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'username': self.username,
            'email': self.email,
            'id': self.id,
            'api_key': self.api_key,
            'is_active': True
        }

class UserSchemaCreateRequest(Schema):
    username = fields.Str(required=True, validate=Length(min=3,max=10))
    email = fields.Email(required=True)
    first_name = fields.Str(required=True, validate=Length(min=3,max=20))
    last_name = fields.Str(required=False)
    password = fields.Str(required=True, validate=Length(min=5,max=15))
    @post_load
    def make_user(self, data,**kwargs):
        return User(**data)

class UserSchemaUpdateRequest(Schema):
    email = fields.Email(required=True)
    first_name = fields.Str(required=True,validate=Length(min=3,max=20))
    last_name = fields.Str(required=False)
    @post_load
    def make_user(self, data,**kwargs):
        return User(**data)

class UserSchemaResponse(Schema):
    id = fields.Integer()
    username = fields.Str(required=True)
    email = fields.Email(required=True)
    first_name = fields.Str(required=True)
    last_name = fields.Str()
    date_added = fields.DateTime()
    date_updated = fields.DateTime()

