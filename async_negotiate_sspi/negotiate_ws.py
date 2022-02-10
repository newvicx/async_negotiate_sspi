import base64
import getpass
import hashlib
import logging
import socket
import struct
from typing import Union

import pywintypes
import sspi
import sspicon
import win32security
from httpx._exceptions import HTTPError
from ws_auth import Auth
from ws_auth.types import Request, Response


logger = logging.getLogger(__name__)


class NegotiateAuthWS(Auth):

    """Negotiate auth handler for WebsocketAuthProtocol"""

    def __init__(
        self,
        service: str = "HTTP",
        username: str = None,
        domain: str = None,
        host: str = None,
        delegate: bool = False,
    ) -> None:

        """
        Create a new Negotiate auth handler
        Args:
            service: Kerberos Service type for remote Service Principal Name.
                Default: 'HTTP'
            username: If specified, will prompt for password
            domain: NT Domain name
                Default: '.' for local account.
            host: Host name for Service Principal Name.
                Default: Extracted from request URI
            delegate: Indicates that the user's credentials are to be delegated to the server.
                Default: False
        If username and password are not specified, the user's default credentials are used.
        This allows for single-sign-on to domain resources if the user is currently logged on
        with a domain account.
        """
        
        self._service = service
        self._auth_info = None
        if username is not None:
            password = getpass.getpass(f"Enter password for user account '{username}': ")
            domain = domain or '.'
            self._auth_info = (username, domain, password)
        self._delegate = delegate
        self._host = host

    def auth_flow(self, request: Request):

        """Perform Negotiate/NTLM authentication steps"""
        
        request_uri = request[0]
        request_headers = request[1]
        if request_headers.get("Authorization") is not None:
            # If auth header provided do nothing
            yield request
            return
        
        response: Response = yield request
        response_headers = response[1]

        scheme = None
        allowed_schemes = ("Negotiate", "NTLM")
        auth_headers = response_headers.get("WWW-Authenticate")
        if not auth_headers:
            return
        for auth_header in auth_headers.split(','):
            if auth_header.strip() in allowed_schemes:
                scheme = auth_header.strip()
                break
        if not scheme:
            # Server did not respond with Negotiate or NTLM
            return
        
        if self._host is None:
            self._host = request_uri.host
            try:
                self._host = socket.getaddrinfo(self._host, None, 0, 0, 0, socket.AI_CANONNAME)[0][3]
                request_headers.pop("Host")
                request_headers.update({"Host": self._host})
            except socket.gaierror as err:
                logger.info('Skipping canonicalization of name %s due to error: %r', self._host, err)
        
        targetspn = '{}/{}'.format(self._service, self._host)

        # request mutual auth by default
        scflags = sspicon.ISC_REQ_MUTUAL_AUTH
        if self._delegate:
            scflags |= sspicon.ISC_REQ_DELEGATE

        pkg_info, clientauth, sec_buffer = self.init_sspi(scheme, targetspn, scflags)
        
        prepped_request = (request_uri, request_headers)
        next_request = self.try_kerberos(prepped_request, response, scheme, pkg_info, clientauth, sec_buffer)

        # send next request
        response: Response = yield next_request
        status_code = response[0]
        if status_code != 401:
            # Kerberos may have succeeded; if so, finalize our auth context
            response_headers = response[1]
            final = response_headers.get("WWW-Authenticate")
            if final is not None:
                try:
                    # Sometimes Windows seems to forget to prepend 'Negotiate' to
                    # the success response, and we get just a bare chunk of base64
                    # token. Not sure why.
                    final = final.replace(scheme, '', 1).lstrip()
                    tokenbuf = win32security.PySecBufferType(pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
                    tokenbuf.Buffer = base64.b64decode(final.encode('ASCII'))
                    sec_buffer.append(tokenbuf)
                    error, auth = clientauth.authorize(sec_buffer)
                    logger.debug(
                        "Kerberos Authentication succeeded - error=%s authenticated=%s",
                        error, clientauth.authenticated
                    )
                except TypeError:
                    pass
            return
        
        # if kerberos failed, do NTLM
        prepped_request = next_request
        next_request = self.try_ntlm(prepped_request, response, scheme, pkg_info, clientauth, sec_buffer)
        
        yield next_request

    def init_sspi(self, scheme: str, targetspn: str, scflags: int) -> Union[
        win32security.QuerySecurityPackageInfo,
        sspi.ClientAuth,
        win32security.PySecBufferDescType
    ]:
        """Set up SSPI connection structure"""

        pkg_info = win32security.QuerySecurityPackageInfo(scheme)
        clientauth = sspi.ClientAuth(
            scheme,
            targetspn=targetspn,
            auth_info=self._auth_info,
            scflags=scflags,
            datarep=sspicon.SECURITY_NETWORK_DREP
        )
        sec_buffer = win32security.PySecBufferDescType()
        return pkg_info, clientauth, sec_buffer

    def try_kerberos(
        self,
        request: Request,
        response: Response,
        scheme: str,
        pkg_info: win32security.QuerySecurityPackageInfo,
        clientauth: sspi.ClientAuth,
        sec_buffer: win32security.PySecBufferDescType
    ) -> None:

        """Do channel binding hash step if SSL. If user has valid TGT, Kerberos should succeed on next request"""

        request_uri = request[0]
        request_headers = request[1]
        response_headers = response[1]

        try:
            request_headers.pop("Authorization")
        except KeyError:
            pass
        # Channel Binding Hash (aka Extended Protection for Authentication)
        # If this is a SSL connection, we need to hash the peer certificate,
        # prepend the RFC5929 channel binding type,
        # and stuff it into a SEC_CHANNEL_BINDINGS structure.
        # This should be sent along in the initial handshake or Kerberos auth will fail.\
        socket = response[3]
        if socket is not None:
            peercert = socket.getpeercert(True)
        if peercert is not None:
            md = hashlib.sha256()
            md.update(peercert)
            appdata = 'tls-server-end-point:'.encode('ASCII')+md.digest()
            logger.debug("Channel binding hash %s", appdata)
            cbtbuf = win32security.PySecBufferType(
                pkg_info['MaxToken'], sspicon.SECBUFFER_CHANNEL_BINDINGS
            )
            cbtbuf.Buffer = struct.pack('LLLLLLLL{}s'.format(len(appdata)), 0, 0, 0, 0, 0, 0, len(appdata), 32, appdata)
            sec_buffer.append(cbtbuf)
        
        # this is important for some web applications that store
        # authentication-related info in cookies
        if response_headers.get("Set-Cookie") is not None:
            request_headers["Cookie"] = response_headers["Set-Cookie"]
        
        try:
            error, auth = clientauth.authorize(sec_buffer)
            auth_header = f"{scheme} {base64.b64encode(auth[0].Buffer).decode('ASCII')}"
            request_headers.update({"Authorization": auth_header})
            logger.debug('Sending Initial Context Token - error=%s authenticated=%s', error, clientauth.authenticated)
        except pywintypes.error as err:
            logger.debug("Error in client auth: %r", repr(err))
            raise err
        return request_uri, request_headers
    
    def try_ntlm(
        self,
        request: Request,
        response: Response,
        scheme: str,
        pkg_info: win32security.QuerySecurityPackageInfo,
        clientauth: sspi.ClientAuth,
        sec_buffer: win32security.PySecBufferDescType
    ) -> None:

        """Get challenge from server and finalize auth context"""

        request_uri = request[0]
        request_headers = request[1]
        response_headers = response[1]

        try:
            request_headers.pop("Authorization")
        except KeyError:
            pass
        # Extract challenge message from server
        challenge_header = response_headers["WWW-Authenticate"]
        challenge = [val[len(scheme)+1:] for val in challenge_header.split(', ') if scheme in val]
        if len(challenge) > 1:
            raise HTTPError(f"Did not get exactly one {scheme} challenge from server.")
        
        tokenbuf = win32security.PySecBufferType(pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
        tokenbuf.Buffer = base64.b64decode(challenge[0])
        sec_buffer.append(tokenbuf)
        logger.debug('Got Challenge Token (NTLM)')

        # Perform next authorization step
        try:
            error, auth = clientauth.authorize(sec_buffer)
            auth_header = f"{scheme} {base64.b64encode(auth[0].Buffer).decode('ASCII')}"
            request_headers.update({"Authorization": auth_header})
            logger.debug('Sending response - error=%s authenticated=%s', error, clientauth.authenticated)
        except pywintypes.error as err:
            logger.debug("Error in client auth: %r", repr(err))
            raise err
        return (request_uri, request_headers)