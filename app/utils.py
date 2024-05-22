import json
import os
from app import app, db
from app.models import User, Question,  CHIFFREMENT_CESARQuestion, GameType
from flask_login import current_user
from sqlalchemy import func
from sqlalchemy.sql import extract
import hashlib
import csv
from datetime import datetime
from collections import OrderedDict


def read_json(path):
    with open(path, "r") as f:
        return json.load(f)

def load_user():
    return User.query.all()


def add_user(name, username, password, **kwargs):
    password = str(hashlib.md5(password.strip().encode('utf-8')).hexdigest())
    user = User(name=name.strip(),
                username=username.strip(),
                password=password,
                email=kwargs.get('email'),
                avatar=kwargs.get('avatar'))
    db.session.add(user)
    db.session.commit()

def check_login(username, password):
    if username and password:
        password = str(hashlib.md5(password.strip().encode('utf-8')).hexdigest())

        return User.query.filter(User.username.__eq__(username.strip()),
                             User.password.__eq__(password)).first()


def get_user_by_id(user_id):
    return User.query.get(user_id)

def load_user():
    users = User.query.filter(User.active.__eq__(True))

    return users

def get_all_questions():
    return Question.query.all()

def get_question_by_id(question_id):
    return Question.query.get(question_id)
