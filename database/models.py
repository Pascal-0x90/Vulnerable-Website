from .db import db
from flask_bcrypt import generate_password_hash, check_password_hash
import random

class Movie(db.Document):
    name = db.StringField(required=True, unique=True)
    casts = db.ListField(db.StringField(), required=True)
    genres = db.ListField(db.StringField(), required=True)
    added_by = db.ReferenceField('User')

class User(db.Document):
    email = db.EmailField(required=True, unique=True)
    password = db.StringField(required=True, min_length=6)
    address = db.StringField(required=True, min_length=5)
    movies = db.ListField(db.ReferenceField('Movie', reverse_delete_rule=db.PULL))
    secret_flag = db.StringField(required=False)

    def set_flag(self):
        # Be cheesy and make a flag
        random_bytes = ''.join([chr(random.randint(97,122)) for _ in range(16)])
        sf = "flag{" + f"{self.email}_{random_bytes}" + "}"
        self.secret_flag = sf
    def hash_password(self):
        self.password = generate_password_hash(self.password).decode('utf8')

    def check_password(self, password):
        return check_password_hash(self.password, password)

User.register_delete_rule(Movie, 'added_by', db.CASCADE)
