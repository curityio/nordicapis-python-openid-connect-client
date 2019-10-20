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
            raise Exception('Server configuration did not contain a revocation endpoint')

        # Exercise 3
        # Add the parameters needed to fullfull the revoke token request.
        # Revoking the Refresh Token should make the Access Token invalid, as well as the refresh token
        data = {'client_id': self.client_config['client_id']}

        return self.__post_request(self.server_config['revocation_endpoint'], data)

    def refresh(self, refresh_token):
        """
        Refresh the access token with the refresh_token
        :param refresh_token:
        :return: the new access token
        """
        # Exercise 2
        # Add the parameters needed to fullfull the refresh token request.
        data = {'client_id': self.client_config['client_id']}

        return self.__post_request(self.server_config['token_endpoint'], data)

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

        # Exercise 1
        # Add the parameters needed to exchange the authorization code for the requested token(s)
        # Only the data map needs to be updated
        # Hint: The client needs to be authenticated, and the token endpoint needs to be instructed what protocol to adhere to.
        data = {
            'client_id': self.client_config['client_id'],
            'redirect_uri': self.client_config['redirect_uri']
        }

        # Exchange code for tokens
        token_data = self.__post_request(self.server_config['token_endpoint'], data)

        if 'id_token' in token_data:
            issuer = self.client_config['issuer']

            # Exercise 4
            # Enforce the correct audience for the id token
            # The validate function will enforce it as long as parameter is set.
            audience = None

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
            raise Exception("Invalid issuer %s, expected %s" % (payload['iss'], iss))

        if aud and payload['aud']:
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
        args = {
            'scope': self.client_config['scope'],
            'response_type': 'code',
            'client_id': self.client_config['client_id'],
            'state': state,
            'redirect_uri': self.client_config['redirect_uri']
        }
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

    def __post_request(self, endpoint, data):
        print('Performing post request to %s' % endpoint)
        try:
            response = urllib.request.urlopen(endpoint, urllib.parse.urlencode(data).encode(), context=self.ctx)
            return json.loads(response.read())
        except urllib.error.HTTPError as e:
            raise Exception("Error response from server. Status code: %s, message: %s" % (e.status, e.reason))
