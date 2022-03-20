"""
Custom Authenticator to use Doorkeeper OAuth with JupyterHub
"""
import os
import warnings
from urllib.parse import quote

from jupyterhub.auth import LocalAuthenticator
from tornado.escape import url_escape
from tornado.httpclient import HTTPRequest
from tornado.httputil import url_concat
from traitlets import CUnicode
from traitlets import default
from traitlets import Set
from traitlets import Unicode

from .oauth2 import OAuthenticator


def _api_headers(access_token):
    return {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
        "Authorization": "Bearer {}".format(access_token),
    }


class DoorkeeperOAuthenticator(OAuthenticator):
    # see doorkeeper_scopes.md for details about scope config
    # set scopes via config, e.g.
    # c.DoorkeeperOAuthenticator.scope = ['read_user']


    login_service = "Doorkeeper"

    client_id_env = 'DOORKEEPER_CLIENT_ID'
    client_secret_env = 'DOORKEEPER_CLIENT_SECRET'

    doorkeeper_url = Unicode("https://doorkeeper.com", config=True)

    @default("doorkeeper_url")
    def _default_doorkeeper_url(self):
        """get default doorkeeper url from env"""
        doorkeeper_url = os.getenv('DOORKEEPER_URL')
        doorkeeper_host = os.getenv('DOORKEEPER_HOST')

        if not doorkeeper_url and doorkeeper_host:
            warnings.warn(
                'Use of DOORKEEPER_HOST might be deprecated in the future. '
                'Rename DOORKEEPER_HOST environment variable to DOORKEEPER_URL.',
                PendingDeprecationWarning,
            )
            if doorkeeper_host.startswith(('https:', 'http:')):
                doorkeeper_url = doorkeeper_host
            else:
                # Hides common mistake of users which set the DOORKEEPER_HOST
                # without a protocol specification.
                doorkeeper_url = 'https://{0}'.format(doorkeeper_host)
                warnings.warn(
                    'The https:// prefix has been added to DOORKEEPER_HOST.'
                    'Set DOORKEEPER_URL="{0}" instead.'.format(doorkeeper_host)
                )

        # default to doorkeeper.com
        if not doorkeeper_url:
            doorkeeper_url = 'https://localhost:3000'

        return doorkeeper_url

    doorkeeper_api_version = CUnicode('1', config=True)

    @default('doorkeeper_api_version')
    def _doorkeeper_api_version_default(self):
        return os.environ.get('DOORKEEPER_API_VERSION') or '1'

    doorkeeper_api = Unicode(config=True)

    @default("doorkeeper_api")
    def _default_doorkeeper_api(self):
        return '%s/api/v%s' % (self.doorkeeper_url, self.doorkeeper_api_version)

    @default("authorize_url")
    def _authorize_url_default(self):
        return "%s/oauth/authorize" % self.doorkeeper_url

    @default("token_url")
    def _token_url_default(self):
        return "%s/oauth/access_token" % self.doorkeeper_url


    doorkeeper_version = None

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")

        # Exchange the OAuth code for a Doorkeeper Access Token
        #
        # See: https://github.com/doorkeeperhq/doorkeeperhq/blob/HEAD/doc/api/oauth2.md

        # Doorkeeper specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            grant_type="authorization_code",
            redirect_uri=self.get_callback_url(handler),
        )

        validate_server_cert = self.validate_server_cert

        url = url_concat("%s/oauth/token" % self.doorkeeper_url, params)

        req = HTTPRequest(
            url,
            method="POST",
            headers={"Accept": "application/json"},
            validate_cert=validate_server_cert,
            body='',  # Body is required for a POST...
        )

        resp_json = await self.fetch(req, label="getting access token")
        access_token = resp_json['access_token']

        # memoize doorkeeper version for class lifetime
        if self.doorkeeper_version is None:
            self.doorkeeper_version = await self._get_doorkeeper_version(access_token)
            self.member_api_variant = 'all/' if self.doorkeeper_version >= [12, 4] else ''

        # Determine who the logged in user is
        req = HTTPRequest(
            "%s/me" % self.doorkeeper_api,
            method="GET",
            validate_cert=validate_server_cert,
            headers=_api_headers(access_token),
        )
        resp_json = await self.fetch(req, label="getting doorkeeper user")

        username = resp_json["username"]
        user_id = resp_json["id"]
        # is_admin = resp_json.get("is_admin", False)


        if ( 1 == 1 ):
            return {
                'name': username,
                'email':email,
                'auth_state': {'access_token': access_token, 'doorkeeper_user': resp_json},
            }
        else:
            self.log.warning("%s not in group or project allowed list", username)
            return None

    async def _get_doorkeeper_version(self, access_token):
        url = '%s/version' % self.doorkeeper_api
        req = HTTPRequest(
            url,
            method="GET",
            headers=_api_headers(access_token),
            validate_cert=self.validate_server_cert,
        )
        resp_json = await self.fetch(req)
        version_strings = resp_json['version'].split('-')[0].split('.')[:3]
        version_ints = list(map(int, version_strings))
        return version_ints



class LocalDoorkeeperOAuthenticator(LocalAuthenticator, DoorkeeperOAuthenticator):

    """A version that mixes in local system user creation"""

    pass