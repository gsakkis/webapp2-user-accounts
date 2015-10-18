import time

from google.appengine.ext import ndb
from webapp2_extras.appengine.auth.models import Unique, UserToken


class User(ndb.Expando):

    unique_model = Unique
    unique_properties = ('email',)
    token_model = UserToken

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    email = ndb.StringProperty(required=True)

    def get_id(self):
        return self._key.id()

    @classmethod
    def get_by_auth_token(cls, user_id, token, subject='auth'):
        token_key = cls.token_model.get_key(user_id, subject, token)
        user_key = ndb.Key(cls, user_id)
        # Use get_multi() to save a RPC call.
        valid_token, user = ndb.get_multi([token_key, user_key])
        if valid_token and user:
            timestamp = int(time.mktime(valid_token.created.timetuple()))
            return user, timestamp
        return None, None

    @classmethod
    def create_auth_token(cls, user_id, subject='auth'):
        return cls.token_model.create(user_id, subject).token

    @classmethod
    def delete_auth_token(cls, user_id, token, subject='auth'):
        cls.token_model.get_key(user_id, subject, token).delete()

    @classmethod
    def create_user(cls, **user_values):
        user = cls(**user_values)

        # Set up unique properties
        uniques = []
        for name in cls.unique_properties:
            key = '%s.%s:%s' % (cls.__name__, name, user_values[name])
            uniques.append((key, name))

        ok, existing = cls.unique_model.create_multi(k for k, v in uniques)
        if ok:
            user.put()
            return True, user
        else:
            properties = [v for k, v in uniques if k in existing]
            return False, properties
