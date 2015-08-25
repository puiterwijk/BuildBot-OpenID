# Copyright (c) 2015, Patrick Uiterwijk <puiterwijk@redhat.com>
# All rights reserved
#
# This file is part of Buildbot-OpenID.  Buildbot-OpenID is free software: you
# can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from buildbot.status.web.authz import Authz
from buildbot.status.web.session import SessionManager
from twisted.internet import defer
from twisted.web import resource
from twisted.python import log

from openid.consumer import consumer
from openid.fetchers import setDefaultFetcher, Urllib2Fetcher
from openid.extensions import sreg
from openid_cla import cla
from openid_teams import teams

COOKIE_KEY = "BuildBotOpenIDSession"


class OpenIDStart(resource.Resource):
    def __init__(self, groups, provider, root_url):
        self.groups = groups
        self.provider = provider
        self.root_url = root_url
        self.isLeaf = True

    def render_GET(self, request):
        session = {}
        oidconsumer = consumer.Consumer(session, None)
        request = oidconsumer.begin(self.provider)
        request.addExtension(sreg.SRegRequest(
            required=['nickname', 'fullname', 'email', 'timezone']))
        request.addExtension(teams.TeamsRequest(requested=self.groups))
        request.addExtension(cla.CLARequest(
            requested=[cla.CLA_URI_FEDORA_DONE]))

        trust_root = self.root_url
        return_to = self.root_url + '_openid_handle/'

        if request.shouldSendRedirect():
            redirect_url = request.redirectURL(trust_root, return_to, False)
            request.redirect(redirect_url)
        else:
            return request.htmlMarkup(
                trust_root, return_to,
                form_tag_attrs={'id': 'openid_message'}, immediate=False)

        try:
            request.finish()
        except RuntimeError:
            # this occurs when the client has already disconnected; ignore
            # it (see #2027)
            log.msg("http client disconnected before results were sent")


class OpenIDHandle(object):
    def __init__(self, root_url):
        self.root_url = root_url
        self.isLeaf = True
        self.sessions = SessionManager()

    def flatten_args(self, request):
        # Flatten args (twisted returns arrays). Just always take first
        args = {}
        for arg in request.args:
            args[arg] = request.args.get(arg)[0]
        return args

    def render(self, request):
        session = {}
        return_to = self.root_url + '_openid_handle/'
        oidconsumer = consumer.Consumer(session, None)
        info = oidconsumer.complete(self.flatten_args(request), return_to)
        display_identifier = info.getDisplayIdentifier()

        if info.status == consumer.FAILURE and display_identifier:
            return 'OpenID Error: %s' % display_identifier
        elif info.status == consumer.CANCEL:
            return 'Cancelled'
        elif info.status == consumer.SUCCESS:
            # Success happened!
            sreg_resp = sreg.SRegResponse.fromSuccessResponse(info)
            teams_resp = teams.TeamsResponse.fromSuccessResponse(info)
            user = {'fullName': '', 'userName': '', 'email': '',
                    'groups': []}
            if not sreg_resp:
                return 'No sreg?'
            user['userName'] = sreg_resp.get('nickname')
            user['fullName'] = sreg_resp.get('fullname')
            user['email'] = sreg_resp.get('email')
            if teams_resp:
                user['groups'] = frozenset(teams_resp.teams)
            cookie, s = self.sessions.new(user['userName'], user)
            request.addCookie(COOKIE_KEY, cookie, expires=s.getExpiration(),
                              path="/")
            request.received_cookies = {COOKIE_KEY: cookie}
            request.redirect(self.root_url)
            return 'DONE'
        else:
            return 'Strange state: %s' % info.status

        try:
            request.finish()
        except RuntimeError:
            # this occurs when the client has already disconnected; ignore
            # it (see #2027)
            log.msg("http client disconnected before results were sent")


class OpenIDAuthz(object):

    """Decide who can do what."""

    def __init__(self,
                 openid_provider,
                 check_certificate=True,
                 **kwargs):
        unknown = []
        self.permissions = {}
        for group in kwargs:
            # Work around the limitations of python identifiers:
            # python identifiers don't support dashes, while unix group names do
            # This is admittedly a hack, but if you have a better way: a PR is welcome
            group = group.replace('_DASH_', '-')

            self.permissions[group] = []
            for perm in kwargs[group]:
                if perm in Authz.knownActions:
                    self.permissions[group].append(perm)
                else:
                    unknown.append(perm)

        self.openid_provider = openid_provider
        self.sessions = SessionManager()
        self.init_childs = False
        if not check_certificate:
            setDefaultFetcher(Urllib2Fetcher())
        # This makes us get self.master as per baseweb.py:472
        self.auth = self
        # This makes the login form be a link
        self.useHttpHeader = True

        if unknown != []:
            raise ValueError('Unknown authorization action(s) ' +
                             ', '.join(unknown))

    def session(self, request):
        if COOKIE_KEY in request.received_cookies:
            cookie = request.received_cookies[COOKIE_KEY]
            return self.sessions.get(cookie)
        return None

    def authenticated(self, request):
        return self.session(request) is not None

    def getUserInfo(self, user):
        s = self.sessions.getUser(user)
        if s:
            return s.infos
        return None

    def getUsername(self, request):
        """Get the userid of the user"""
        s = self.session(request)
        if s:
            return s.user
        return '<unknown>'

    def getUsernameHTML(self, request):
        """Get the user formatted in html (with possible link to email)"""
        s = self.session(request)
        if s:
            return s.userInfosHTML().decode('UTF-8')
        return "not authenticated?!"

    def getUsernameFull(self, request):
        """Get the full username as fullname <email>"""
        s = self.session(request)
        if s:
            return "%(fullName)s <%(email)s>" % (s.infos)
        else:
            return request.args.get("username", ["<unknown>"])[0]

    def getPassword(self, request):
        return '<no-password>'

    def create_childs(self, request):
        # We need to create the childs with this workaround
        #  because we won't get the site information prior
        #  to handling the very first request
        if not self.init_childs:
            self.init_childs = True
            status = request.site.buildbot_service.master.status
            root = status.getBuildbotURL()
            self.httpLoginUrl = '%s/_openid_start/' % root
            request.site.resource.putChild('_openid_start',
                                           OpenIDStart(self.permissions.keys(),
                                                       self.openid_provider,
                                                       root))
            request.site.resource.putChild('_openid_handle',
                                           OpenIDHandle(root))

    def shouldAllowAction(self, action, request):
        self.create_childs(request)

        if action in self.permissions.get('_all_', []):
            return True
        s = self.sessions.getUser(request)
        if s:
            if action in self.permissions.get('_authenticated_', []):
                return True
            for group in s.infos['groups']:
                if action in self.permissions.get(group, []):
                    return True
        return False

    def advertiseAction(self, action, request):
        """Should the web interface even show the form for ACTION?"""
        if action not in Authz.knownActions:
            raise KeyError("unknown action")
        return self.shouldAllowAction(action, request)

    def actionAllowed(self, action, request, *args):
        """Is this ACTION allowed, given this http REQUEST?"""
        if action not in Authz.knownActions:
            raise KeyError("unknown action")
        return defer.succeed(self.shouldAllowAction(action, request))

    def logout(self, request):
        if COOKIE_KEY in request.received_cookies:
            cookie = request.received_cookies[COOKIE_KEY]
            self.sessions.remove(cookie)
