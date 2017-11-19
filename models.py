# to avoid the generation of .pyc files

import sys

sys.dont_write_bytecode = True

import datetime

# to handle error:  'ImportError: Failed to import _strptime because the import lockis
# held by another thread'

throwaway = datetime.datetime.strptime('20110101','%Y%m%d')


from flask.ext.bcrypt import generate_password_hash
from flask.ext.login import UserMixin, AnonymousUserMixin
from peewee import *

DATABASE = SqliteDatabase('var/updated-social.db')


# user class to save our user's personal details
class User(UserMixin, Model):
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField(max_length=100)
    joined_at = DateTimeField(default=datetime.datetime.now)
    is_admin = BooleanField(default=False)

    class Meta:
       database = DATABASE
       order_by = ('-joined_at',)

    def get_posts(self):
      return Post.select().where(Post.user == self)

    def get_stream(self):
      return Post.select().where(
       (Post.user << self.following()) |
       (Post.user == self)
        )

    def following(self):
    # The users that we are following 
      return (
        User.select().join(
          Relationship, on=Relationship.to_user
        ).where(
          Relationship.from_user == self  
        )
       )

    def followers(self):
    # Get users following the current user
      return (
        User.select().join(
          Relationship, on=Relationship.from_user
       ).where(
          Relationship.to_user == self   
       )
      )

    @classmethod
    def create_user(cls, username, email, password, admin=False):
      try:
        with DATABASE.transaction():
          cls.create(
              username=username,
              email=email,
              password=generate_password_hash(password),
              is_admin=admin)
      except IntegrityError:
        raise ValueError("User already exists")

class Anonymous(AnonymousUserMixin):
    username = u"Anonymous"


# new Post class to save user posts
class Post(Model):
  timestamp = DateTimeField(default=datetime.datetime.now)
  user =ForeignKeyField(
    rel_model=User,
    related_name='posts'
  )
  content = TextField()

#we use negative timestamp to return the newest posts first
  class Meta:
    database = DATABASE
    order_by = ('-timestamp',)

class Relationship(Model):
  from_user = ForeignKeyField(User, related_name='relationships')
  to_user = ForeignKeyField(User, related_name='related_to')

  class Meta:
    database = DATABASE
    indexes = (
          (('from_user','to_user'),True)
      )

class TrackSessions(Model) :
    timestamp = DateTimeField(default=datetime.datetime.now)
    userID = ForeignKeyField(User)
    session = CharField()
    Ip_address = CharField()

    class Meta:
        database = DATABASE
        order_by = ('-timestamp',)

def initialize():
  DATABASE.get_conn()
  DATABASE.create_tables([User,Post, Relationship, TrackSessions],safe=True)
  DATABASE.close()
