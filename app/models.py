from sqlalchemy import Column, Integer, Boolean, Float, String, Text, ForeignKey, Enum, DateTime, Time
from sqlalchemy.orm import relationship, backref
from app import db, app
from datetime import datetime
from flask_login import UserMixin
from enum import Enum as UserEnum


class BaseModel(db.Model):
    __abstract__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)

class User(BaseModel, UserMixin):
    name = Column(String(50), nullable=True)
    username = Column(String(50), nullable=True, unique=True)
    password = Column(String(50), nullable=True)
    avatar = Column(String(100))
    email = Column(String(50), nullable=True, unique=True)
    active = Column(Boolean, default=True)
    joined_date = Column(DateTime, default=datetime.now())


if __name__ == '__main__':
    with app.app_context():
        db.create_all()