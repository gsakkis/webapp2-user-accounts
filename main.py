#!/usr/bin/env python

import logging
import os.path
import webapp2

from webapp2_extras import auth, sessions
from google.appengine.ext.webapp import template

from models import User


config = {
    'webapp2_extras.auth': {
        'user_model': User,
        'user_attributes': ['name']
    },
    'webapp2_extras.sessions': {
        'secret_key': 'YOUR_SECRET_KEY'
    }
}


def user_required(handler):
    """
      Decorator that checks if there's a user associated with the current session.
      Will also fail if there's no session present.
    """
    def check_login(self, *args, **kwargs):
        if not self.user_info:
            return self.redirect(self.uri_for('login'), abort=True)
        return handler(self, *args, **kwargs)
    return check_login


class BaseHandler(webapp2.RequestHandler):

    @webapp2.cached_property
    def user_info(self):
        """Shortcut to access a subset of the user attributes that are stored
        in the session.

        The list of attributes to store in the session is specified in
          config['webapp2_extras.auth']['user_attributes'].
        :returns
          A dictionary with most user information
        """
        return auth.get_auth().get_user_by_session()

    def render_template(self, view_filename, params=None):
        if not params:
            params = {}
        params['user'] = self.user_info
        path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
        return self.response.out.write(template.render(path, params))

    def display_message(self, message):
        """Utility function to display a template with a simple message."""
        return self.render_template('message.html', {'message': message})

    # this is needed for webapp2 sessions to work
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)
        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)


class MainHandler(BaseHandler):

    def get(self):
        return self.render_template('home.html')


class SignupHandler(BaseHandler):

    def get(self):
        return self.render_template('signup.html')

    def post(self):
        email = self.request.get('email')
        user_data = User.create_user(email=email,
                                     name=self.request.get('name'),
                                     last_name=self.request.get('lastname'),
                                     verified=False)
        if not user_data[0]:  # user_data is a tuple
            return self.display_message(
                'Unable to create user for email %s because of duplicate keys %s'
                % (email, user_data[1]))

        user_id = user_data[1].get_id()
        verification_type = 'signup'
        token = User.create_auth_token(user_id, verification_type)
        verification_url = self.uri_for('verification',
                                        verification_type=verification_type,
                                        user_id=user_id, token=token, _full=True)

        msg = 'Send an email to user in order to verify their address. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'

        return self.display_message(msg.format(url=verification_url))


class LoginHandler(BaseHandler):

    def get(self):
        return self._serve_page(self.request.get('email'), not_found=False)

    def post(self):
        email = self.request.get('email')
        user = User.query(User.email == email).get()
        if not user:
            logging.info('Could not find any user entry for email %s', email)
            return self._serve_page(email, not_found=True)

        user_id = user.get_id()
        verification_type = 'reset'
        token = User.create_auth_token(user_id, verification_type)
        verification_url = self.uri_for('verification',
                                        verification_type=verification_type,
                                        user_id=user_id, token=token, _full=True)

        msg = 'Send an email to user to allow them to login. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'

        return self.display_message(msg.format(url=verification_url))

    def _serve_page(self, email, not_found):
        return self.render_template('login.html', {'email': email,
                                                   'not_found': not_found})


class VerificationHandler(BaseHandler):

    def get(self, verification_type, user_id, token):
        user, ts = User.get_by_auth_token(int(user_id), token, verification_type)
        if not user:
            logging.info('Could not find any user with id "%s" token "%s"',
                         user_id, token)
            self.abort(404, 'This link has expired')

        # remove token, we don't want users to come back with an old link
        User.delete_auth_token(user.get_id(), token, verification_type)

        # store user data in the session
        auth_obj = auth.get_auth()
        # invalidate current session (if any) and set a new one
        auth_obj.unset_session()
        auth_obj.set_session(auth_obj.store.user_to_dict(user), remember=True)

        if verification_type == 'signup':
            if not user.verified:
                user.verified = True
                user.put()
            return self.display_message('User email address has been verified.')
        elif verification_type == 'reset':
            return self.redirect(self.uri_for('home'))

        assert False, verification_type


class LogoutHandler(BaseHandler):

    def get(self):
        auth.get_auth().unset_session()
        return self.redirect(self.uri_for('home'))


class AuthenticatedHandler(BaseHandler):

    @user_required
    def get(self):
        return self.render_template('authenticated.html')


app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/signup', SignupHandler),
    webapp2.Route(r'/<verification_type:signup|reset>/<user_id:\d+>/<token:.+>',
                  VerificationHandler, name='verification'),
    webapp2.Route('/login', LoginHandler, name='login'),
    webapp2.Route('/logout', LogoutHandler),
    webapp2.Route('/authenticated', AuthenticatedHandler)
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
