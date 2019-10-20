##########################################################################
# Copyright 2019 Curity AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

import json
import string
import base64
import random
from flask import redirect, request, render_template, session, Flask
from client import Client

global _app
_app = Flask(__name__)


class UserSession:
    def __init__(self):
        pass

    access_token = None
    refresh_token = None
    id_token = None


@_app.route('/')
def index():
    """
    :return: the index page with the tokens, if set.
    """
    user = None
    if 'session_id' in session:
        user = _session_store.get(session['session_id'])

    if user:
        return render_template('index.html',
                               server_name=_config['issuer'],
                               session=user)
    else:
        return render_template('welcome.html')


@_app.route('/start-login')
def start_code_flow():
    """
    :return: redirects to the authorization server with the appropriate parameters set.
    """
    state = generate_random_string()
    session['state'] = state
    login_url = _client.get_authorization_request_url(state)
    return redirect(login_url)


@_app.route('/logout')
def logout():
    """
    Logout clears the session, along with the tokens
    :return: redirects to /
    """
    if 'session_id' in session:
        del _session_store[session['session_id']]
    session.clear()
    if 'logout_endpoint' in _config:
        print("Logging out against", _config['logout_endpoint'])
        return redirect(_config['logout_endpoint'] + '?redirect_uri=' + _config['base_url'])
    return redirect_with_baseurl('/')


@_app.route('/refresh')
def refresh():
    """
    Refreshes the access token using the refresh token
    :return: redirects to /
    """
    user = _session_store.get(session['session_id'])
    try:
        token_data = _client.refresh(user.refresh_token)
    except Exception as e:
        create_error('Could not refresh Access Token', e)
        return
    user.access_token = token_data['access_token']
    user.refresh_token = token_data['refresh_token']
    return redirect_with_baseurl('/')


@_app.route('/revoke')
def revoke():
    """
    Revokes the access and refresh token and clears the sessions
    :return: redirects to /
    """
    if 'session_id' in session:
        user = _session_store.get(session['session_id'])
        if not user:
            redirect_with_baseurl('/')

        if user.refresh_token:
            try:
                _client.revoke(user.refresh_token)
            except Exception as e:
                return create_error('Could not revoke refresh token', e)
            user.refresh_token = None

    return redirect_with_baseurl('/')


@_app.route('/callback')
def oauth_callback():
    """
    Called when the resource owner is returning from the authorization server
    :return:redirect to / with user info stored in the session.
    """
    if 'state' not in session or session['state'] != request.args['state']:
        return create_error('Missing or invalid state')

    if 'code' not in request.args:
        return create_error('No code in response')

    try:
        token_data = _client.get_token(request.args['code'])
    except Exception as e:
        return create_error('Could not fetch token(s)', e)
    session.pop('state', None)

    # Store tokens in basic server session, since flask session use cookie for storage
    user = UserSession()

    if 'access_token' in token_data:
        user.access_token = token_data['access_token']

    if 'id_token' in token_data:
        user.id_token = token_data['id_token']

    if 'refresh_token' in token_data:
        user.refresh_token = token_data['refresh_token']

    session['session_id'] = generate_random_string()
    _session_store[session['session_id']] = user

    return redirect_with_baseurl('/')


def create_error(message, exception=None):
    """
    Print the error and output it to the page
    :param message:
    :return: redirects to index.html with the error message
    """
    print('Caught error!')
    error_message = "%s: %s" % (message, exception)
    print(error_message)
    if _app:
        user = None
        if 'session_id' in session:
            user = _session_store.get(session['session_id'])
        return render_template('index.html',
                               server_name=_config['issuer'],
                               session=user,
                               error=error_message)


def load_config():
    """
    Load config from config file
    :return: a map of the config
    """
    filename = 'client_config.json'
    print('Loading settings from %s' % filename)

    return json.loads(open(filename).read())


def redirect_with_baseurl(path):
    return redirect(_config['base_url'] + path)


def get_config_or_default(config_key, config, default):
    if config_key in config:
        return config[config_key]
    return default


def base64_urldecode(s):
    ascii_string = str(s)
    ascii_string += '=' * (4 - (len(ascii_string) % 4))
    return base64.urlsafe_b64decode(ascii_string)


def generate_random_string(size=20):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def start(config):
    # load the config
    global _config
    _config = config

    # some default values
    debug = get_config_or_default('debug', _config, True)
    port = get_config_or_default('port', _config, 9080)
    _config['base_url'] = get_config_or_default('base_url', _config, '')
    _config['verify_ssl_server'] = get_config_or_default('verify_ssl_server', _config, True)

    # Create the client
    global _client
    _client = Client(_config)

    # create a session store
    global _session_store
    _session_store = {}

    # initiate the app
    _app.secret_key = generate_random_string()
    _app.run('0.0.0.0', debug=debug, port=port)
