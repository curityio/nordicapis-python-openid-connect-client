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
import ssl
import random
import string
import base64
import urllib.request
import urllib.parse
import urllib.error
import jwkest.jwk
import jwkest.jws
from jwkest import BadSignature


class Client:
    def __init__(self, client_config):
        self.client_config = client_config

        print('Getting ssl context for oauth server')
        self.ctx = self.__get_ssl_context(self.client_config)
        self.__validate_client_config()
        self.server_config = self.__get_server_config()

        self.jwks = self.__load_keys()

    def revoke(self, token):
        """
        Revoke the token
        :param token: the token to revoke
        :raises: raises error when http call fails
        """
        if 'revocation_endpoint' not in self.server_config:
            print('No revocation endpoint set')
            return

        revoke_request = urllib.request.Request(
            self.server_config['revocation_endpoint'])
        data = {'client_id': self.client_config['client_id'],
                'client_secret': self.client_config['client_secret'],
                'token': token}
        urllib.request.urlopen(revoke_request, urllib.parse.urlencode(data).encode(), context=self.ctx)

    def refresh(self, refresh_token):
        """
        Refresh the access token with the refresh_token
        :param refresh_token:
        :return: the new access token
        """
        data = {'client_id': self.client_config['client_id'],
                'client_secret': self.client_config['client_secret'],
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'}
        token_response = urllib.request.urlopen(self.server_config['token_endpoint'], urllib.parse.urlencode(data).encode(), context=self.ctx)
        return json.loads(token_response.read())

    def get_authorization_request_url(self, state):
        """
        :param state: the random state for this request
        :return full authorization request url with parameters
        """
        request_args = self.__authorization_request_args(state)

        login_url = "%s?%s" % (self.server_config['authorization_endpoint'], urllib.parse.urlencode(request_args))
        print("Redirect to authorization endpoint %s" % login_url)
        return login_url

    def get_token(self, code):
        """
        :param code: The authorization code to use when getting tokens
        :return the json response containing the tokens
        """

        data = {'client_id': self.client_config['client_id'],
                'redirect_uri': self.client_config['redirect_uri'],
                'client_secret': self.client_config['client_secret'],
                'code': code,
                'grant_type': 'authorization_code'}

        # Exchange code for tokens
        try:
            token_response = urllib.request.urlopen(self.server_config['token_endpoint'], urllib.parse.urlencode(data).encode(), context=self.ctx)
        except urllib.error.URLError as te:
            print("Could not exchange code for tokens")
            raise te

        token_data = json.loads(token_response.read())

        if 'id_token' in token_data:
            audience = self.client_config['client_id']
            issuer = self.client_config['issuer']

            self.__validate_jwt(token_data['id_token'], issuer, audience)

        return token_data

    def __validate_jwt(self, jwt, iss, aud):
        parts = jwt.split('.')
        if len(parts) != 3:
            raise BadSignature('Invalid JWT. Only JWS supported.')

        jws = jwkest.jws.JWS()
        # Raises exception when signature is invalid
        try:
            payload = jws.verify_compact(jwt, self.jwks)
        except Exception as e:
            print('Exception validating signature')
            raise e

        if iss != payload['iss']:
            raise Exception("Invalid issuer %s, expected %s" %
                            (payload['iss'], iss))

        if payload['aud']:
            if (isinstance(payload['aud'], str) and payload['aud'] != aud) or aud not in payload['aud']:
                raise Exception("Invalid audience %s, expected %s" % (payload['aud'], aud))

        print('Successfully validated signature')

    def __load_keys(self):
        return jwkest.jwk.load_jwks_from_url(self.server_config['jwks_uri'], self.client_config['verify_ssl_server'])

    def __authorization_request_args(self, state):
        """
        :param state: state to send to authorization server
        :return a map of arguments to be sent to the authz endpoint
        """
        args = {'scope': self.client_config['scope'],
                'response_type': 'code',
                'client_id': self.client_config['client_id'],
                'state': state,
                'redirect_uri': self.client_config['redirect_uri']}
        return args

    def __validate_client_config(self):
        # Checking that the client config is there
        if 'client_id' not in self.client_config:
            raise Exception('client_id not set.')

        if 'client_secret' not in self.client_config:
            raise Exception('client_secret not set.')

        if 'redirect_uri' not in self.client_config:
            raise Exception('redirect_uri not set.')

    def __get_server_config(self):
        # discover all the endpoints from the discovery document
        server_config = {}
        if 'issuer' in self.client_config:
            discovery_url = self.client_config['issuer'] + '/.well-known/openid-configuration'
            print("Get server configuration from %s" % discovery_url)
            discovery = urllib.request.urlopen(discovery_url, context=self.ctx)
            server_config.update(json.loads(discovery.read()))
        else:
            raise Exception("No issuer configured")

        # Mandatory settings
        if 'authorization_endpoint' not in server_config:
            print(server_config)
            raise Exception('authorization_endpoint not set.')

        if 'token_endpoint' not in server_config:
            print(server_config)
            raise Exception('token_endpoint not set.')

        if 'jwks_uri' not in server_config:
            print(server_config)
            raise Exception('jwks_uri not set')

        return server_config

    def __get_ssl_context(self, config):
        """
        :return a ssl context with verify and hostnames settings
        """
        ctx = ssl.create_default_context()

        if 'verify_ssl_server' in config and not config['verify_ssl_server']:
            print('Not verifying ssl certificates')
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx
