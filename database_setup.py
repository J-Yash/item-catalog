from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

# USER CLASS


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

# BAKERY CLASS


class Bakery(Base):
    __tablename__ = 'bakery'

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
# CODE FOR JSON API ENDPOINT

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
        }

# MENUITEM CLASS


class MenuItem(Base):
    __tablename__ = 'menu_item'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    price = Column(String(8))
    bakery_id = Column(Integer, ForeignKey('bakery.id'))
    bakery = relationship(Bakery)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
# CODE FOR JSON API ENDPOINT

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'price': self.price,
        }

# CONNECTING TO DATABASE
engine = create_engine('sqlite:///pastryparadise.db')


Base.metadata.create_all(engine)
