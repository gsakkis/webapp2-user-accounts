import time

from google.appengine.ext import ndb
from webapp2_extras import auth, security
from webapp2_extras.appengine.auth.models import Unique, UserToken


class User(ndb.Expando):

    unique_model = Unique
    unique_properties = ('auth_id', 'email_address')
    token_model = UserToken

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    # ID for third party authentication, e.g. 'google:username'. UNIQUE.
    auth_ids = ndb.StringProperty(repeated=True)
    password = ndb.StringProperty()

    def get_id(self):
        return self._key.id()

    @classmethod
    def get_by_auth_id(cls, auth_id):
        return cls.query(cls.auth_ids == auth_id).get()

    @classmethod
    def get_by_auth_password(cls, auth_id, password):
        user = cls.get_by_auth_id(auth_id)
        if not user:
            raise auth.InvalidAuthIdError()
        if not security.check_password_hash(password, user.password):
            raise auth.InvalidPasswordError()
        return user

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
    def create_user(cls, auth_id, **user_values):
        assert user_values.get('password') is None, \
            'Use password_raw instead of password to create new users.'

        assert not isinstance(auth_id, list), \
            'Creating a user with multiple auth_ids is not allowed, ' \
            'please provide a single auth_id.'

        if 'password_raw' in user_values:
            user_values['password'] = security.generate_password_hash(
                user_values.pop('password_raw'), length=12)

        user_values['auth_ids'] = [auth_id]
        user = cls(**user_values)

        # Set up unique properties
        uniques = []
        user_values['auth_id'] = auth_id
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
