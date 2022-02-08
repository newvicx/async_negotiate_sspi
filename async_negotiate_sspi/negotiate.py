import base64
import getpass
import hashlib
import logging
import socket
import struct
from typing import TypeVar, Union

import pywintypes
import sspi
import sspicon
import win32security

from httpcore.backends.asyncio import AsyncIOStream
try:
    from httpcore.backends.trio import TrioStream
except (ImportError, ModuleNotFoundError):
    from httpcore.backends.base import AsyncNetworkStream
    TrioStream = TypeVar("TrioStream", bound=AsyncNetworkStream)
from httpx import Auth, Request
from httpx._exceptions import HTTPError
from httpx_extensions import ResponseMixin


logger = logging.getLogger(__name__)


class NegotiateAuth(Auth):

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
        
        if request.headers.get("authorization") is not None:
            # If auth header provided do nothing
            yield request
            return
        
        response: ResponseMixin = yield request

        scheme = None
        allowed_schemes = ("Negotiate", "NTLM")
        for auth_header in response.headers.get_list("www-authenticate"):
            if auth_header.strip() in allowed_schemes:
                scheme = auth_header.strip()
                break
        if not scheme:
            # Server did not respond with Negotiate or NTLM
            return
        
        if self._host is None:
            self._host = request.url.host
            try:
                self._host = socket.getaddrinfo(self._host, None, 0, 0, 0, socket.AI_CANONNAME)[0][3]
                request.headers["host"] = self._host
            except socket.gaierror as err:
                logger.info('Skipping canonicalization of name %s due to error: %r', self._host, err)
        
        targetspn = '{}/{}'.format(self._service, self._host)

        # request mutual auth by default
        scflags = sspicon.ISC_REQ_MUTUAL_AUTH
        if self._delegate:
            scflags |= sspicon.ISC_REQ_DELEGATE

        pkg_info, clientauth, sec_buffer = self.init_sspi(scheme, targetspn, scflags)
        
        self.try_kerberos(request, response, scheme, pkg_info, clientauth, sec_buffer)

        # Get conn_id so next request can go out on same connection
        conn_id = response.extensions.get("conn_id")
        if not conn_id:
            logger.warning("No conn_id returned in response")
        else:
            logger.debug("Using conn_id %s", conn_id)
        request.extensions.update({"conn_id": conn_id})

        # send next request
        response: ResponseMixin = yield request
        
        if response.status_code != 401:
            # Kerberos may have succeeded; if so, finalize our auth context
            final = response.headers.get("www-authenticate")
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
        self.try_ntlm(request, response, scheme, pkg_info, clientauth, sec_buffer)
        
        yield request

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
        response: ResponseMixin,
        scheme: str,
        pkg_info: win32security.QuerySecurityPackageInfo,
        clientauth: sspi.ClientAuth,
        sec_buffer: win32security.PySecBufferDescType
    ) -> None:

        """Do channel binding hash step if SSL. If user has valid TGT, Kerberos should succeed on next request"""

        # Channel Binding Hash (aka Extended Protection for Authentication)
        # If this is a SSL connection, we need to hash the peer certificate,
        # prepend the RFC5929 channel binding type,
        # and stuff it into a SEC_CHANNEL_BINDINGS structure.
        # This should be sent along in the initial handshake or Kerberos auth will fail.
        stream: Union[AsyncIOStream, TrioStream] = response.extensions.get("network_stream")
        if hasattr(stream, "peercert") and stream.peercert is not None:
            peercert = stream.peercert
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
        if response.headers.get("set-cookie") is not None:
            request.headers["cookie"] = response.headers["set-cookie"]
        
        try:
            error, auth = clientauth.authorize(sec_buffer)
            auth_header = f"{scheme} {base64.b64encode(auth[0].Buffer).decode('ASCII')}"
            request.headers["authorization"] = auth_header
            logger.debug('Sending Initial Context Token - error=%s authenticated=%s', error, clientauth.authenticated)
        except pywintypes.error as err:
            logger.debug("Error in client auth: %r", repr(err))
            raise err
        return
    
    def try_ntlm(
        self,
        request: Request,
        response: ResponseMixin,
        scheme: str,
        pkg_info: win32security.QuerySecurityPackageInfo,
        clientauth: sspi.ClientAuth,
        sec_buffer: win32security.PySecBufferDescType
    ) -> None:

        """Get challenge from server and finalize auth context"""

        # Extract challenge message from server
        challenge_header = response.headers["www-authenticate"]
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
            request.headers["authorization"] = auth_header
            logger.debug('Sending response - error=%s authenticated=%s', error, clientauth.authenticated)
        except pywintypes.error as err:
            logger.debug("Error in client auth: %r", repr(err))
            raise err
        return